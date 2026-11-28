package rw.login;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Blocks an IP address after too many wrong passwords. Kept in memory. */
final class IpGuard {
    private final Map<String, long[]> map = new ConcurrentHashMap<>();

    /** Seconds this IP is still blocked, or 0. */
    long blockedFor(String ip) {
        long[] v = map.get(ip);
        if (v == null) return 0;
        long left = v[1] - System.currentTimeMillis();
        return left > 0 ? (left + 999) / 1000 : 0;
    }

    /** Count one wrong password. Returns true if the IP is now blocked. */
    boolean fail(String ip, int max, long lockSeconds) {
        long now = System.currentTimeMillis();
        long[] v = map.compute(ip, (k, old) -> {
            long[] n = old == null ? new long[]{0, 0} : old;
            if (n[1] != 0 && n[1] <= now) {
                n[0] = 0;
                n[1] = 0;
            }
            n[0]++;
            if (n[0] >= max) n[1] = now + lockSeconds * 1000L;
            return n;
        });
        return v[1] > now;
    }
}
