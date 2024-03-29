<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\{
    HashAlgorithm,
    S2kType,
};

/**
 * String-to-key class
 * 
 * Implementation of the String-to-key specifier
 * String-to-key (S2K) specifiers are used to convert passphrase strings into
 * symmetric-key encryption/decryption keys.
 * They are used in two places, currently: to encrypt the secret part
 * of private keys in the private keyring, and to convert passphrases
 * to encryption keys for symmetrically encrypted messages.
 *
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class S2K
{
    /**
     * Default salt length
     */
    const SALT_LENGTH = 8;

    /**
     * Exponent bias, defined in RFC4880
     */
    const EXPBIAS = 6;

    /**
     * Default iteration count byte
     */
    const DEFAULT_IT_COUNT = 224;

    private readonly int $count;

    /**
     * Constructor
     *
     * @return self
     */
    public function __construct(
        private readonly string $salt,
        private readonly S2kType $type = S2kType::Iterated,
        private readonly HashAlgorithm $hash = HashAlgorithm::Sha1,
        private readonly int $itCount = self::DEFAULT_IT_COUNT
    )
    {
        $this->count = (16 + ($itCount & 15)) << (($itCount >> 4) + self::EXPBIAS);
    }

    /**
     * Get S2K type
     *
     * @return S2kType
     */
    public function getType(): S2kType
    {
        return $this->type;
    }

    /**
     * Get hash algorithm
     *
     * @return HashAlgorithm
     */
    public function getHashAlgorithm(): HashAlgorithm
    {
        return $this->hash;
    }

    /**
     * Get salt
     *
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * Get iteration count
     *
     * @return int
     */
    public function getItCount(): int
    {
        return $this->itCount;
    }

    /**
     * Get packet length
     *
     * @return int
     */
    public function getLength(): int
    {
        return $this->type->packetLength();
    }

    /**
     * Parsing function for a string-to-key specifier
     * 
     * @param string $bytes - Payload of string-to-key specifier
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $salt = '';
        $itCount = self::DEFAULT_IT_COUNT;

        $type = S2kType::from(ord($bytes[0]));
        $hash = HashAlgorithm::from(ord($bytes[1]));
        switch ($type) {
            case S2kType::Salted:
                $salt = substr($bytes, 2, 8);
                break;
            case S2kType::Iterated:
                $salt = substr($bytes, 2, 8);
                $itCount = ord($bytes[10]);
                break;
        }
        return new self($salt, $type, $hash, $itCount);
    }

    /**
     * Serialize s2k information to binary string
     * 
     * @return string
     */
    public function toBytes(): string
    {
        return match($this->type) {
            S2kType::Simple => implode([
                chr($this->type->value),
                chr($this->hash->value)],
            ),
            S2kType::Salted => implode([
                chr($this->type->value),
                chr($this->hash->value),
                $this->salt,
            ]),
            S2kType::Iterated => implode([
                chr($this->type->value),
                chr($this->hash->value),
                $this->salt,
                chr($this->itCount),
            ]),
            S2kType::GNU => implode([
                chr($this->type->value),
                'GNU',
                "\x01",
            ]),
        };
    }

    /**
     * Produce a key using the specified passphrase and the defined hash algorithm
     * 
     * @param string $passphrase
     * @param int $keyLen
     * @return string
     */
    public function produceKey(
        string $passphrase, int $keyLen
    ): string
    {
        return match($this->type) {
            S2kType::Simple => $this->hash($passphrase, $keyLen),
            S2kType::Salted => $this->hash(
                $this->salt . $passphrase, $keyLen
            ),
            S2kType::Iterated => $this->hash(
                $this->iterate($this->salt . $passphrase), $keyLen
            ),
            S2kType::GNU => $this->hash($passphrase, $keyLen),
        };
    }

    private function iterate(string $data): string
    {
        if(strlen($data) >= $this->count) return $data;
        $data = str_repeat(
            $data, (int) ceil($this->count / strlen($data))
        );
        return substr($data, 0, $this->count);
    }

    private function hash(string $data, int $size): string
    {
        $alg = strtolower($this->hash->name);
        $hash = hash($alg, $data, true);
        while(strlen($hash) < $size) {
            $data = "\x00" . $data;
            $hash .= hash($alg, $data, true);
        }
        return substr($hash, 0, $size);
    }
}
