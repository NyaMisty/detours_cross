extern "C" {
    static int g_lastError = 0;
    
    void SetLastError(int err) {
        g_lastError = err;
    }
    
    int GetLastError() {
        return g_lastError;
    }

}