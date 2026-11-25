package edu.unsl.ciberlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Filtro de limitación de tasa (Rate Limiting) por IP para proteger el servidor
 * compartido de la Sala de Máquinas ante ráfagas o scripts automatizados.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 60_000L;
    private static final int MAX_TRACKED_IPS = 1000;

    private final int maxRequestsPerMinute;
    private final Map<String, WindowCounter> counters = new ConcurrentHashMap<>();

    public RateLimitFilter(@Value("${app.ratelimit.requests-per-minute:90}") int maxRequestsPerMinute) {
        this.maxRequestsPerMinute = Math.max(10, maxRequestsPerMinute);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null || !path.startsWith("/api/")) {
            return true;
        }
        // Excluir endpoints de lectura frecuente de estado y ranking en vivo
        return path.equals("/api/ctf/leaderboard")
                || path.equals("/api/ctf/status")
                || path.equals("/api/classroom/state");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String clientIp = resolveClientIp(request);
        long now = System.currentTimeMillis();

        if (counters.size() > MAX_TRACKED_IPS) {
            counters.entrySet().removeIf(entry -> now - entry.getValue().windowStart > WINDOW_MS);
        }

        WindowCounter counter = counters.compute(clientIp, (key, existing) -> {
            if (existing == null || now - existing.windowStart >= WINDOW_MS) {
                return new WindowCounter(now);
            }
            return existing;
        });

        int currentCount = counter.count.incrementAndGet();
        response.setHeader("X-RateLimit-Limit", String.valueOf(maxRequestsPerMinute));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, maxRequestsPerMinute - currentCount)));

        if (currentCount > maxRequestsPerMinute) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(
                    "{\"error\":\"RATE_LIMIT_EXCEEDED\","
                    + "\"message\":\"Límite de peticiones por minuto alcanzado (" + maxRequestsPerMinute
                    + " req/min). Espera unos segundos antes de continuar para no saturar el servidor del aula.\"}"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown";
    }

    private static final class WindowCounter {
        final long windowStart;
        final AtomicInteger count = new AtomicInteger(0);

        WindowCounter(long windowStart) {
            this.windowStart = windowStart;
        }
    }
}
