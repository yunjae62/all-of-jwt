package ex.jwtnew.global.redis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedisUtil {

    private final ObjectMapper objectMapper;
    private final StringRedisTemplate redisTemplate;

    public <T> Optional<T> get(String key, Class<T> clazz) {
        try {
            String value = redisTemplate.opsForValue().get(key);

            if (value == null) {
                return Optional.empty();
            }

            return Optional.of(objectMapper.readValue(value, clazz));
        } catch (JsonProcessingException e) {
            log.error("redis json parsing error", e);
            throw new HttpClientErrorException(HttpStatusCode.valueOf(500));
        }
    }

    public <T> void set(String key, T value) {
        try {
            String jsonValue = objectMapper.writeValueAsString(value);
            redisTemplate.opsForValue().set(key, jsonValue);
        } catch (JsonProcessingException e) {
            log.error("redis json serialization error", e);
            throw new HttpClientErrorException(HttpStatusCode.valueOf(500));
        }
    }

    public <T> void set(String key, T value, Duration ttl) {
        try {
            String jsonValue = objectMapper.writeValueAsString(value);
            redisTemplate.opsForValue().set(key, jsonValue, ttl);
        } catch (JsonProcessingException e) {
            log.error("redis json serialization error", e);
            throw new HttpClientErrorException(HttpStatusCode.valueOf(500));
        }
    }

    public void delete(String key) {
        redisTemplate.delete(key);
    }
}
