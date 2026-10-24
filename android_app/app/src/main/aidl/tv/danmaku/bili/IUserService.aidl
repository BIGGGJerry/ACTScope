package tv.danmaku.bili;
interface IUserService {
    void destroy() = 16777114;
    String startWatch(String configJson) = 1;
    String stopWatch() = 2;
    String status() = 3;
    String scanFiles(String configJson) = 4;
    String startManualWatch(String configJson, in byte[] replacementApk) = 5;
    String attemptHijack(String watchId, String candidateId, boolean normalBaselineVerified) = 6;
}
