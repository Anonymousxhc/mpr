package io.research.mpvhbypass;

import java.io.BufferedReader;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public final class Main implements IXposedHookLoadPackage {

    private static final String TARGET = "com.nic.mparivahan";
    private static final String TAG = "mpvh-bypass";

    // Anchored to NextGen mParivahan 2.0.144 / versionCode 304 (sha256 198d7337...b169).
    // Zepto AppProtect renames these per build; the generic anchors are what keep the
    // module working, the named ones are secondary coverage.
    private static final String[] TRUST_MANAGERS = {
        "com.zepto.dk", "com.zepto.qk0", "com.zepto.Au1$a", "com.zepto.zu1$a"
    };
    private static final String PIN_QUEUE = "com.zepto.eu1";
    private static final String ROOTBEER = "com.zepto.a51";
    private static final String ROOTBEER_NATIVE = "com.scottyab.rootbeer.RootBeerNative";

    private static final String[] ROOT_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/sbin/", "/sbin/.magisk",
        "/data/local/tmp/magisk", "/data/adb/magisk", "/data/adb/modules",
        "/dev/.magisk", "/debug_ramdisk/su", "/system/app/Superuser.apk",
        "/system/bin/.ext", "/data/local/xsu", "/data/local/bin/su"
    };
    private static final String[] FRAMEWORK_MARKERS = {
        "de.robv.android.xposed", "org.lsposed", "lspd", "frida", "gum_trace",
        "fridaRuleObject", "magisk", "ririsu", "me.weishu.epic", "com.saurik.substrate"
    };

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) {
        if (!TARGET.equals(lpparam.packageName)) return;
        log("attached to " + lpparam.packageName);

        installPinningBypass(lpparam.classLoader);
        installRootBypass(lpparam.classLoader);
        installDetectionBypass();

        // Zepto binds its own classes late; re-apply once the real names arrive.
        XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class,
                new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) {
                String name = (String) p.args[0];
                if (name == null) return;
                if (name.equals(PIN_QUEUE) || name.equals(ROOTBEER)
                        || name.equals(ROOTBEER_NATIVE) || contains(TRUST_MANAGERS, name)) {
                    installPinningBypass(lpparam.classLoader);
                    installRootBypass(lpparam.classLoader);
                }
            }
        });
    }

    private static boolean contains(String[] set, String value) {
        for (String s : set) if (s.equals(value)) return true;
        return false;
    }

    // --- TLS pinning ---------------------------------------------------------------
    // No res/xml exists in this APK, so there is no network_security_config pin:
    // pinning is entirely in-app (Zepto's Volley queue + custom trust managers).
    // Swapping the TrustManager[] handed to SSLContext.init covers them all without
    // depending on an obfuscated class name.

    private static final X509TrustManager ACCEPT_ALL = new X509TrustManager() {
        @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
        @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
        @Override public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    private void installPinningBypass(ClassLoader loader) {
        hook(SSLContext.class, "init", new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam p) {
                p.args[1] = new TrustManager[]{ACCEPT_ALL};
            }
        }, KeyManager[].class, TrustManager[].class, java.security.SecureRandom.class);

        hook("android.net.http.X509TrustManagerExtensions", loader, "checkServerTrusted",
                new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam p) {
                        p.setResult(p.args[0]);
                    }
                }, String.class, String.class, List.class);

        // Absent in 2.0.144; harmless coverage if a later build adds OkHttp.
        hook("okhttp3.CertificatePinner", loader, "check",
                bypass(), String.class, List.class);
        hook("okhttp3.CertificatePinner", loader, "check",
                bypass(), String.class, X509Certificate[].class);

        final HostnameVerifier allowHost = new HostnameVerifier() {
            @Override public boolean verify(String h, SSLSession s) { return true; }
        };
        try { HttpsURLConnection.setDefaultHostnameVerifier(allowHost); }
        catch (Throwable t) { log("default hostname verifier untouched: " + t); }
        hook(HttpsURLConnection.class, "setHostnameVerifier", new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam p) {
                p.args[0] = allowHost;
            }
        }, HostnameVerifier.class);

        for (String name : TRUST_MANAGERS) {
            Class<?> tm = XposedHelpers.findClassIfExists(name, loader);
            if (tm == null) continue;
            XposedBridge.hookAllMethods(tm, "checkServerTrusted", bypass());
            XposedBridge.hookAllMethods(tm, "checkClientTrusted", bypass());
            hook(tm, "getAcceptedIssuers", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    p.setResult(new X509Certificate[0]);
                }
            });
            log("neutered trust manager " + name);
        }

        // eu1.i([X509Certificate,String)Z is the comparator; eu1.g([...,String,I)V raises.
        Class<?> queue = XposedHelpers.findClassIfExists(PIN_QUEUE, loader);
        if (queue != null) {
            hook(queue, "i", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    p.setResult(Boolean.FALSE);
                }
            }, X509Certificate[].class, String.class);
            hook(queue, "g", bypass(), X509Certificate[].class, String.class, int.class);
            log("neutered " + PIN_QUEUE + " pin check");
        }
    }

    // --- root detection ------------------------------------------------------------
    // RootBeer's native class kept its real name through R8, so it is the stable anchor.
    // com.zepto.a51 is the renamed RootBeer wrapper: every boolean-returning method there
    // is a root predicate (busybox, magisk, su, which-su, ro.debuggable, test-keys,
    // rw-mount), so stubbing the whole set is deliberate rather than a spray.

    private void installRootBypass(ClassLoader loader) {
        Class<?> beerNative = XposedHelpers.findClassIfExists(ROOTBEER_NATIVE, loader);
        if (beerNative != null) {
            hook(beerNative, "checkForRoot", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    p.setResult(0);
                }
            }, Object[].class);
            hook(beerNative, "setLogDebugMessages", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    p.setResult(0);
                }
            }, boolean.class);
            try { XposedHelpers.setStaticBooleanField(beerNative, "a", false); }
            catch (Throwable t) { log("RootBeerNative.a not settable"); }
            log("neutralised RootBeerNative");
        }

        Class<?> beer = XposedHelpers.findClassIfExists(ROOTBEER, loader);
        if (beer != null) {
            XC_MethodHook falseResult = new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    p.setResult(Boolean.FALSE);
                }
            };
            int hooked = 0;
            for (Method m : beer.getDeclaredMethods()) {
                if (m.getReturnType() != boolean.class) continue;
                XposedBridge.hookAllMethods(beer, m.getName(), falseResult);
                hooked++;
            }
            log("false-baked " + hooked + " root predicates in " + ROOTBEER);
        }

        XC_MethodHook pathGuard = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) {
                if (!(p.thisObject instanceof java.io.File)) return;
                String path = ((java.io.File) p.thisObject).getAbsolutePath();
                for (String bad : ROOT_PATHS) {
                    if (path.startsWith(bad)) { p.setResult(Boolean.FALSE); return; }
                }
            }
        };
        XposedBridge.hookAllMethods(java.io.File.class, "exists", pathGuard);
        XposedBridge.hookAllMethods(java.io.File.class, "canRead", pathGuard);
        XposedBridge.hookAllMethods(java.io.File.class, "canExecute", pathGuard);

        XC_MethodHook execGuard = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam p) {
                String cmd = p.args[0] instanceof String[]
                        ? join((String[]) p.args[0])
                        : String.valueOf(p.args[0]);
                if (cmd.contains("/su") || cmd.contains("su -c") || cmd.contains("which su")
                        || cmd.endsWith(" su") || cmd.contains("magisk")
                        || cmd.contains("busybox")) {
                    p.args[0] = new String[]{"/system/bin/toybox", "id"};
                }
            }
        };
        hook(Runtime.class, "exec", execGuard, String.class);
        hook(Runtime.class, "exec", execGuard, String[].class);

        Class<?> sysProps = XposedHelpers.findClassIfExists(
                "android.os.SystemProperties", loader);
        if (sysProps != null) {
            hook(sysProps, "get", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    String key = String.valueOf(p.args[0]);
                    if ("ro.debuggable".equals(key) || "ro.kernel.qemu".equals(key)) {
                        p.setResult("0");
                    } else if ("ro.secure".equals(key)) {
                        p.setResult("1");
                    }
                }
            }, String.class, String.class);
            hook(sysProps, "getBoolean", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam p) {
                    if ("ro.debuggable".equals(String.valueOf(p.args[0]))) {
                        p.setResult(Boolean.FALSE);
                    }
                }
            }, String.class, boolean.class);
        }

        try { XposedHelpers.setStaticObjectField(android.os.Build.class, "TAGS", "release-keys"); }
        catch (Throwable t) { log("Build.TAGS unchanged: " + t); }
    }

    // --- hook-framework detection --------------------------------------------------
    // com.zepto PR1/kq0/lh0/vZ0 carry the "xposed" and fridaRuleObject markers.
    // Best effort only: LSPosed's own hide plus a Magisk DenyList entry for this
    // package does more than anything in this method.

    private void installDetectionBypass() {
        hook(Class.class, "forName", new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam p)
                    throws Throwable {
                String name = String.valueOf(p.args[0]);
                for (String marker : FRAMEWORK_MARKERS) {
                    if (name.contains(marker)) throw new ClassNotFoundException(name);
                }
            }
        }, String.class, boolean.class, ClassLoader.class);

        XC_MethodHook scrub = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) {
                Object res = p.getResult();
                if (res == null || !res.getClass().isArray()) return;
                List<Object> keep = new ArrayList<>();
                for (int i = 0; i < Array.getLength(res); i++) {
                    Object e = Array.get(res, i);
                    String s = e == null ? "" : e.toString();
                    boolean drop = false;
                    for (String marker : FRAMEWORK_MARKERS) {
                        if (s.contains(marker)) { drop = true; break; }
                    }
                    if (!drop) keep.add(e);
                }
                if (keep.size() != Array.getLength(res)) {
                    Object out = Array.newInstance(res.getClass().getComponentType(),
                            keep.size());
                    for (int i = 0; i < keep.size(); i++) Array.set(out, i, keep.get(i));
                    p.setResult(out);
                }
            }
        };
        XposedBridge.hookAllMethods(Throwable.class, "getStackTrace", scrub);
        XposedBridge.hookAllMethods(Thread.class, "getStackTrace", scrub);

        // Only maps/mount style lines carry a path separator, so requiring one keeps
        // this off ordinary app text (the dex contains "friday_13_november", which
        // would otherwise match "frida" and truncate a real stream).
        hook(BufferedReader.class, "readLine", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) {
                String line = (String) p.getResult();
                if (line == null || line.indexOf('/') < 0) return;
                String lower = line.toLowerCase();
                for (String marker : FRAMEWORK_MARKERS) {
                    if (lower.contains(marker.toLowerCase())) {
                        p.setResult(null);
                        return;
                    }
                }
            }
        });
    }

    private static String join(String[] parts) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    private static XC_MethodHook bypass() {
        return new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam p) {
                p.setResult(null);
            }
        };
    }

    private static void hook(Class<?> cls, String method, XC_MethodHook cb, Class<?>... params) {
        try {
            Object[] args = new Object[params.length + 1];
            System.arraycopy(params, 0, args, 0, params.length);
            args[params.length] = cb;
            XposedHelpers.findAndHookMethod(cls, method, args);
        } catch (Throwable t) {
            log("hook failed " + cls.getName() + "." + method + ": " + t);
        }
    }

    private static void hook(String clsName, ClassLoader loader, String method,
                             XC_MethodHook cb, Class<?>... params) {
        Class<?> cls = XposedHelpers.findClassIfExists(clsName, loader);
        if (cls != null) hook(cls, method, cb, params);
    }

    private static void log(String msg) {
        XposedBridge.log(TAG + ": " + msg);
    }
}
