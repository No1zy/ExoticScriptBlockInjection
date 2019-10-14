package breakscripttag;

import burp.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.DataNode;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

public class PerRequestScans implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private List<Function<IHttpRequestResponse, IScanIssue>> scanChecks;

    PerRequestScans(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.scanChecks = new ArrayList<>();
        this.scanChecks.add(withScriptInjection());
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        if (!shouldTriggerPerRequestAttacks(baseRequestResponse, insertionPoint)) return null;

        List<IScanIssue> issues = new ArrayList<>();
        for (Function<IHttpRequestResponse, IScanIssue> scanCheck : this.scanChecks) {
            IScanIssue issue = scanCheck.apply(baseRequestResponse);
            if (Objects.nonNull(issue)) issues.add(issue);
        }

        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    private Function<IHttpRequestResponse, IScanIssue> withScriptInjection() {
        return (IHttpRequestResponse baseRequestResponse) -> {

            IRequestInfo requestInfo = this.helpers.analyzeRequest(baseRequestResponse.getRequest());
            byte request[] = baseRequestResponse.getRequest();
            List<IParameter> parameters = requestInfo.getParameters();
            byte payloads[][] = new byte[][]{
                    "<!--<script>".getBytes(),
                    "<!--</script>".getBytes(),
                    "<!-- <script>".getBytes(),
                    "<!-- </script>".getBytes(),
                    "<!--hukjfa<script>".getBytes(),
                    "<!--hukjfa</script>".getBytes(),
                    "<!--<<script>".getBytes(),
                    "<!--<</script>".getBytes(),
                    "<!--</<script>".getBytes(),
                    "<!--</</script>".getBytes(),
                    "<!--</</script>".getBytes(),
                    "<!--\n<script>".getBytes(),
                    "<!--\n</script>".getBytes(),
                    "<!--\n</script>".getBytes(),
                    "<!--!><script>".getBytes(),
                    "<!--!></script>".getBytes(),
            };

            for (IParameter parameter : parameters) {
                int paramStartOffset = parameter.getValueStart();
                int paramEndOffset = parameter.getValueEnd();
                byte requestStartParts[] = Arrays.copyOfRange(request, 0, paramStartOffset);
                byte requestEndParts[] = Arrays.copyOfRange(request, paramEndOffset, request.length);
                for (byte payload[] : payloads) {
                    byte[] customRequest = new byte[requestStartParts.length + payload.length + requestEndParts.length];
                    System.arraycopy(requestStartParts, 0, customRequest, 0, requestStartParts.length);
                    System.arraycopy(payload, 0, customRequest, paramStartOffset, payload.length);
                    System.arraycopy(requestEndParts, 0, customRequest, paramStartOffset + payload.length, requestEndParts.length);
                    System.out.println("Request: " + new String(customRequest));
                    IHttpRequestResponse attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), customRequest);

                    Document doc = Jsoup.parse(new String(attack.getResponse()));

                    Elements scripts = doc.getElementsByTag("script");
                    for (Element script : scripts) {
                        for (DataNode node : script.dataNodes()) {

                            if (node.getWholeData().contains(new String(payload))) {
                                IHttpRequestResponse httpMessages[] = {attack};
                                return new CustomIssue(
                                        this.helpers.analyzeRequest(attack).getUrl(),
                                        "Broken Script tag injection",
                                        "Medium",
                                        "Certain",
                                        "For historical reasons script blocks are known to make exotic parse.\n" +
                                                "Reference: https://html.spec.whatwg.org/multipage/scripting.html#restrictions-for-contents-of-script-elements",
                                        "this issue lead client side DoS or XSS.",
                                        "Unicode escape to '<'>'.",
                                        httpMessages,
                                        baseRequestResponse.getHttpService()
                                );

                            }
                        }
                    }
                }
            }

            return null;
        };
    }

    private boolean shouldTriggerPerRequestAttacks(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IRequestInfo request = this.helpers.analyzeRequest(baseRequestResponse.getRequest());
        List<IParameter> params = request.getParameters();

        if (params.size() > 0) {
            int firstParameterOffset = 999999;
            IParameter firstParameter = null;
            byte paramTypes[] = {
                    IParameter.PARAM_BODY,
                    IParameter.PARAM_URL,
                    IParameter.PARAM_JSON,
                    IParameter.PARAM_XML,
                    IParameter.PARAM_XML_ATTR,
                    IParameter.PARAM_MULTIPART_ATTR,
                    IParameter.PARAM_COOKIE
            };
            for (byte paramType : paramTypes) {
                for (IParameter param : params) {
                    if (param.getType() != paramType) continue;

                    if (param.getNameStart() < firstParameterOffset) {
                        firstParameterOffset = param.getNameStart();
                        firstParameter = param;
                    }
                }
                if (Objects.nonNull(firstParameter)) break;
            }

            if (Objects.nonNull(firstParameter) && firstParameter.getName().equals(insertionPoint.getInsertionPointName())) {
                return true;
            }
        } else if (insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER &&
                insertionPoint.getInsertionPointName().equals("User-Agent")) {
            return true;
        }

        return false;
    }

    class CustomIssue implements IScanIssue {
        private URL url;
        private String issueName;
        private String severity;
        private String confidence;
        private String issueBackground;
        private String issueDetail;
        private String remediationDetail;
        private IHttpRequestResponse[] httpMessages;
        private IHttpService httpService;


        public CustomIssue(URL url, String issueName, String severity,
                           String confidence, String issueBackground, String issueDetail,
                           String remediationDetail, IHttpRequestResponse[] httpMessages, IHttpService httpService) {
            this.url = url;
            this.issueName = issueName;
            this.severity = severity;
            this.confidence = confidence;
            this.issueBackground = issueBackground;
            this.issueDetail = issueDetail;
            this.remediationDetail = remediationDetail;
            this.httpMessages = httpMessages;
            this.httpService = httpService;
        }

        @Override
        public URL getUrl() {
            return this.url;
        }

        @Override
        public String getIssueName() {
            return this.issueName;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return this.severity;
        }

        @Override
        public String getConfidence() {
            return this.confidence;
        }

        @Override
        public String getIssueBackground() {
            return this.issueBackground;
        }

        @Override
        public String getRemediationBackground() {
            return null;
        }

        @Override
        public String getIssueDetail() {
            return this.issueDetail;
        }

        @Override
        public String getRemediationDetail() {
            return this.remediationDetail;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return this.httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return this.httpService;
        }
    }

}
