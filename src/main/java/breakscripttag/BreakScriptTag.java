package breakscripttag;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

public class BreakScriptTag implements IBurpExtender {
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        callbacks.setExtensionName("Broken Script tag injection");

        callbacks.registerScannerCheck(new PerRequestScans(callbacks));
    }
}
