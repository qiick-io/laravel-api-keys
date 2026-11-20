<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Decides whether last_used_* should be written for this request.
 */
final class UsageRecorder
{
    public function shouldRecord(
        \DateTimeImmutable $now,
        ?\DateTimeImmutable $lastUsedAt,
        ?string $lastUsedIp,
        ?string $currentIp,
        int $throttleSeconds = 60, // @pest-mutate-ignore
        bool $bypassThrottleOnIpChange = true, // @pest-mutate-ignore
    ): bool {
        if ($lastUsedAt === null) {
            return true; // @pest-mutate-ignore RemoveEarlyReturn — null would error on getTimestamp below
        }

        if (
            $bypassThrottleOnIpChange
            && $currentIp !== null
            && $currentIp !== $lastUsedIp
        ) {
            return true;
        }

        return ($now->getTimestamp() - $lastUsedAt->getTimestamp()) >= $throttleSeconds;
    }
}
