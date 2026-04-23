package de.robv.android.xposed;

public abstract class XC_MethodHook {
    public static class MethodHookParam {
        public Object[] args;

        public Object getResult() {
            return null;
        }
    }

    protected void afterHookedMethod(MethodHookParam param) throws Throwable {}
}
