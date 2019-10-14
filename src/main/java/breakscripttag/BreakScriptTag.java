package breakscripttag;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

public class BreakScriptTag implements IBurpExtender {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Broken Script tag injection");

        callbacks.registerScannerCheck(new PerRequestScans(callbacks));
    }
}
