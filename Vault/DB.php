<?php
namespace Vault;

use PDO;
use PDOException;
use Exception;

class DB {
    private static ?PDO $pdo = null;

    /**
     * Get or initialize the PDO instance.
     * @return PDO
     * @throws Exception
     */
    public static function getConn(): PDO {
        if (self::$pdo === null) {
            $configPath = dirname(__FILE__) . '/config.php';
            if (!file_exists($configPath)) {
                throw new Exception("CRXSM is not installed. Configuration file is missing.");
            }

            $config = require($configPath);

            $host = $config['db']['host'] ?? 'localhost';
            $db   = $config['db']['name'] ?? '';
            $user = $config['db']['user'] ?? '';
            $pass = $config['db']['pass'] ?? '';
            $port = $config['db']['port'] ?? '3306';
            $charset = 'utf8mb4';

            $dsn = "mysql:host=$host;dbname=$db;port=$port;charset=$charset";
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];

            try {
                self::$pdo = new PDO($dsn, $user, $pass, $options);
            } catch (PDOException $e) {
                throw new Exception("Database connection failed: " . $e->getMessage());
            }
        }
        return self::$pdo;
    }

    /**
     * Run a query and return statement.
     */
    public static function query(string $sql, array $params = []): \PDOStatement {
        $stmt = self::getConn()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /**
     * Fetch a single row.
     */
    public static function fetch(string $sql, array $params = []): ?array {
        $stmt = self::query($sql, $params);
        $res = $stmt->fetch();
        return $res ? $res : null;
    }

    /**
     * Fetch all matching rows.
     */
    public static function fetchAll(string $sql, array $params = []): array {
        return self::query($sql, $params)->fetchAll();
    }

    /**
     * Execute a statement (INSERT/UPDATE/DELETE) and return row count or success.
     */
    public static function execute(string $sql, array $params = []): bool {
        return self::query($sql, $params) !== null;
    }

    /**
     * Get the last inserted ID.
     */
    public static function lastInsertId(): string {
        return self::getConn()->lastInsertId();
    }

    /**
     * Execute a closure inside a transaction.
     */
    public static function transaction(callable $callback) {
        $conn = self::getConn();
        $conn->beginTransaction();
        try {
            $result = $callback($conn);
            $conn->commit();
            return $result;
        } catch (Exception $e) {
            $conn->rollBack();
            throw $e;
        }
    }
}
