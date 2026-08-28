<?php

declare(strict_types=1);

namespace Namingo\Bind9Api;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use InvalidArgumentException;
use JsonException;
use RuntimeException;

final class ApiClient
{
    private Client $client;
    private ?string $authToken = null;

    /**
     * The legacy debug/basic-auth arguments remain for compatibility with the
     * standalone client. Normal API authentication is performed by login().
     *
     * @param array<string, mixed> $clientOptions Additional Guzzle options.
     */
    public function __construct(
        string $baseUrl,
        bool $debugMode = false,
        ?string $username = null,
        ?string $password = null,
        array $clientOptions = []
    ) {
        $baseUrl = rtrim(trim($baseUrl), '/');
        $parts = parse_url($baseUrl);
        if (
            filter_var($baseUrl, FILTER_VALIDATE_URL) === false
            || !is_array($parts)
            || !in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || !in_array((string) ($parts['path'] ?? ''), ['', '/'], true)
        ) {
            throw new InvalidArgumentException(
                'A valid HTTP(S) API origin URL without a path, query, fragment, or embedded credentials is required.'
            );
        }

        $customHeaders = is_array($clientOptions['headers'] ?? null) ? $clientOptions['headers'] : [];
        unset($clientOptions['headers']);
        $config = array_replace([
            'base_uri' => $baseUrl,
            'timeout' => 10.0,
            'connect_timeout' => 5.0,
            'allow_redirects' => false,
        ], $clientOptions);
        $config['headers'] = array_merge([
            'Accept' => 'application/json',
            'User-Agent' => 'Namingo-Bind9ApiClient/1.0',
        ], $customHeaders);

        if ($debugMode && $username !== null && $password !== null) {
            $config['auth'] = [$username, $password];
        }

        $this->client = new Client($config);
    }

    public function login(string $username, string $password): void
    {
        if ($username === '' || $password === '') {
            throw new InvalidArgumentException('Username and password are required.');
        }

        try {
            $response = $this->client->post('/login', [
                'json' => ['username' => $username, 'password' => $password],
            ]);
            $data = $this->decode($response->getBody()->getContents());
            $token = $data['token'] ?? null;

            if (!is_string($token) || !preg_match('/^[a-f0-9]{64}$/i', $token)) {
                throw new RuntimeException('The login response did not contain a valid token.');
            }

            $this->authToken = $token;
        } catch (RequestException $e) {
            throw new RuntimeException('Authentication failed: ' . $this->requestError($e), 0, $e);
        } catch (GuzzleException | JsonException $e) {
            throw new RuntimeException('Authentication failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /** @return array<string, mixed> */
    public function getZones(): array
    {
        return $this->request('GET', '/zones');
    }

    /** @return array<string, mixed> */
    public function getSlaveZones(): array
    {
        return $this->request('GET', '/slave-zones');
    }

    /** @return array<string, mixed> */
    public function addZone(string $zoneName, array $options = []): array
    {
        return $this->request('POST', '/zones', [
            'json' => array_merge($options, ['zone' => $zoneName]),
        ]);
    }

    /** @return array<string, mixed> */
    public function addSlaveZone(string $zoneName, string $masterIp): array
    {
        return $this->request('POST', '/slave-zones', [
            'json' => ['zone' => $zoneName, 'master_ip' => $masterIp],
        ]);
    }

    /** @return array<string, mixed> */
    public function deleteZone(string $zoneName): array
    {
        return $this->request('DELETE', '/zones/' . $this->segment($zoneName));
    }

    /** @return array<string, mixed> */
    public function deleteSlaveZone(string $zoneName): array
    {
        return $this->request('DELETE', '/slave-zones/' . $this->segment($zoneName));
    }

    /** @return array<string, mixed> */
    public function getRecords(string $zoneName): array
    {
        return $this->request('GET', '/zones/' . $this->segment($zoneName) . '/records');
    }

    /**
     * @param array<string, mixed> $record Keys: name, type, ttl and rdata.
     * @return array<string, mixed>
     */
    public function addRecord(string $zoneName, array $record): array
    {
        return $this->request('POST', '/zones/' . $this->segment($zoneName) . '/records', [
            'json' => $record,
        ]);
    }

    /**
     * @param array<string, mixed> $currentRecord Keys: name, type and rdata.
     * @param array<string, mixed> $newRecord Keys: name, ttl, rdata and/or comment.
     * @return array<string, mixed>
     */
    public function updateRecord(string $zoneName, array $currentRecord, array $newRecord): array
    {
        foreach (['name', 'type', 'rdata'] as $required) {
            if (!array_key_exists($required, $currentRecord) || $currentRecord[$required] === '') {
                throw new InvalidArgumentException('Current record name, type, and rdata are required.');
            }
        }

        $payload = [
            'current_name' => $currentRecord['name'],
            'current_type' => strtoupper((string) $currentRecord['type']),
            'current_rdata' => $currentRecord['rdata'],
        ];

        $map = [
            'name' => 'new_name',
            'ttl' => 'new_ttl',
            'rdata' => 'new_rdata',
            'comment' => 'new_comment',
        ];
        foreach ($map as $source => $destination) {
            if (array_key_exists($source, $newRecord)) {
                $payload[$destination] = $newRecord[$source];
            }
        }

        return $this->request(
            'PUT',
            '/zones/' . $this->segment($zoneName) . '/records/update',
            ['json' => $payload]
        );
    }

    /**
     * @param array<string, mixed> $record Keys: name, type and rdata.
     * @return array<string, mixed>
     */
    public function deleteRecord(string $zoneName, array $record): array
    {
        foreach (['name', 'type', 'rdata'] as $required) {
            if (!array_key_exists($required, $record) || $record[$required] === '') {
                throw new InvalidArgumentException('Record name, type, and rdata are required.');
            }
        }

        return $this->request(
            'DELETE',
            '/zones/' . $this->segment($zoneName) . '/records/delete',
            ['json' => [
                'name' => $record['name'],
                'type' => strtoupper((string) $record['type']),
                'rdata' => $record['rdata'],
            ]]
        );
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function request(string $method, string $uri, array $options = []): array
    {
        if ($this->authToken === null) {
            throw new RuntimeException('Call login() before making an API request.');
        }

        $options['headers'] = array_merge(
            $options['headers'] ?? [],
            ['Authorization' => 'Bearer ' . $this->authToken]
        );

        try {
            $response = $this->client->request($method, $uri, $options);
            return $this->decode($response->getBody()->getContents());
        } catch (RequestException $e) {
            throw new RuntimeException('API request failed: ' . $this->requestError($e), 0, $e);
        } catch (GuzzleException | JsonException $e) {
            throw new RuntimeException('API request failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /** @return array<string, mixed> */
    private function decode(string $body): array
    {
        $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new JsonException('The API response must be a JSON object.');
        }

        return $data;
    }

    private function requestError(RequestException $exception): string
    {
        if (!$exception->hasResponse()) {
            return $exception->getMessage();
        }

        $response = $exception->getResponse();
        $body = trim($response->getBody()->getContents());
        $body = $body === '' ? 'empty response body' : substr($body, 0, 1000);

        return sprintf('HTTP %d: %s', $response->getStatusCode(), $body);
    }

    private function segment(string $value): string
    {
        $value = trim($value);
        if ($value === '') {
            throw new InvalidArgumentException('Zone name is required.');
        }

        return rawurlencode($value);
    }
}
