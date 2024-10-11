<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\{HashAlgorithm, S2kType};
use OpenPGP\Type\S2KInterface;

/**
 * Implementation of the String-to-key specifier
 *
 * See RFC 9580, section 3.7.
 *
 * A string-to-key (S2K) Specifier is used to convert a passphrase string into a
 * symmetric key encryption/decryption key.
 * Passphrases requiring use of S2K conversion are currently used in two places:
 * to encrypt the secret part of private keys and for symmetrically encrypted messages.
 *
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class GenericS2K implements S2KInterface
{
    use S2KTrait;

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

    /**
     * The number of resulting count
     */
    private readonly int $count;

    /**
     * Constructor
     *
     * @param string $salt
     * @param S2kType $type
     * @param HashAlgorithm $hash
     * @param int $itCount
     * @return self
     */
    public function __construct(
        private readonly string $salt,
        private readonly S2kType $type = S2kType::Iterated,
        private readonly HashAlgorithm $hash = HashAlgorithm::Sha256,
        private readonly int $itCount = self::DEFAULT_IT_COUNT
    ) {
        if ($type === S2kType::Argon2) {
            throw new \InvalidArgumentException(
                "S2k type {$type->name} is invalid argument."
            );
        }
        $this->count = 16 + ($itCount & 15) << ($itCount >> 4) + self::EXPBIAS;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return match ($this->type) {
            S2kType::Simple => implode([
                chr($this->type->value),
                chr($this->hash->value),
            ]),
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
            S2kType::GNU => implode([chr($this->type->value), "GNU", "\x01"]),
            default => "",
        };
    }

    /**
     * {@inheritdoc}
     */
    public function produceKey(string $passphrase, int $length): string
    {
        return match ($this->type) {
            S2kType::Simple => $this->hash($passphrase, $length),
            S2kType::Salted => $this->hash($this->salt . $passphrase, $length),
            S2kType::Iterated => $this->hash(
                $this->iterate($this->salt . $passphrase),
                $length
            ),
            S2kType::GNU => $this->hash($passphrase, $length),
            default => "",
        };
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
     * Get iteration count
     *
     * @return int
     */
    public function getItCount(): int
    {
        return $this->itCount;
    }

    /**
     * Parsing function for a string-to-key specifier
     *
     * @param string $bytes - Payload of string-to-key specifier
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $type = S2kType::from(ord($bytes[0]));
        $hash = HashAlgorithm::from(ord($bytes[1]));

        $salt = match ($type) {
            S2kType::Salted, S2kType::Iterated => substr(
                $bytes,
                2,
                self::SALT_LENGTH
            ),
            default => "",
        };
        $itCount = $type === S2kType::Iterated
            ? ord($bytes[self::SALT_LENGTH + 2])
            : 0;
        return new self($salt, $type, $hash, $itCount);
    }

    private function iterate(string $data): string
    {
        if (strlen($data) >= $this->count) {
            return $data;
        }
        $data = str_repeat($data, (int) ceil($this->count / strlen($data)));
        return substr($data, 0, $this->count);
    }

    private function hash(string $data, int $size): string
    {
        $hash = $this->hash->hash($data);
        while (strlen($hash) < $size) {
            $data = "\x00" . $data;
            $hash .= $this->hash->hash($data);
        }
        return substr($hash, 0, $size);
    }
}
