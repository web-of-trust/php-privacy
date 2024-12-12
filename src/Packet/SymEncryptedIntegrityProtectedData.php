<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\{Config, Helper};
use OpenPGP\Enum\{AeadAlgorithm, HashAlgorithm, PacketTag, SymmetricAlgorithm};
use OpenPGP\Type\{
    AeadEncryptedDataPacketInterface,
    PacketListInterface,
    SessionKeyInterface
};
use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Random;

/**
 * Implementation of the Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
 *
 * See RFC 9580, section 5.13.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SymEncryptedIntegrityProtectedData
    extends AbstractPacket
    implements AeadEncryptedDataPacketInterface
{
    use AeadEncryptedDataTrait, EncryptedDataTrait;

    const VERSION_1 = 1;
    const VERSION_2 = 2;
    const HASH_ALGO = "sha1";
    const MDC_SUFFIX = "\xd3\x14";
    const SALT_SIZE = 32;

    /**
     * Constructor
     *
     * @param int $version
     * @param string $encrypted
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @param int $chunkSize
     * @param string $salt
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(
        private readonly int $version,
        private readonly string $encrypted,
        private readonly ?SymmetricAlgorithm $symmetric = null,
        private readonly ?AeadAlgorithm $aead = null,
        private readonly int $chunkSize = 12,
        private readonly string $salt = "",
        private readonly ?PacketListInterface $packetList = null
    ) {
        parent::__construct(
            PacketTag::SymEncryptedIntegrityProtectedData
        );
        if ($version !== self::VERSION_1 && $version !== self::VERSION_2) {
            throw new \InvalidArgumentException(
                "Version $version of the SEIPD packet is unsupported."
            );
        }
        $isV2 = $version === self::VERSION_2;
        if ($symmetric instanceof SymmetricAlgorithm && $isV2) {
            Helper::assertSymmetric($symmetric);
        }
        if ($aead instanceof AeadAlgorithm && !$isV2) {
            throw new \InvalidArgumentException(
                "Using AEAD with v{$version} SEIPD packet is not allowed."
            );
        }
        if (!empty($salt) && strlen($salt) !== self::SALT_SIZE) {
            throw new \LengthException(
                "Salt size must be " . self::SALT_SIZE . " bytes."
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        // A one-octet version number.
        $version = ord($bytes[$offset++]);

        if ($version === self::VERSION_2) {
            // - A one-octet cipher algorithm.
            $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));

            // - A one-octet AEAD algorithm.
            $aead = AeadAlgorithm::from(ord($bytes[$offset++]));

            // - A one-octet chunk size.
            $chunkSize = ord($bytes[$offset++]);

            // Thirty-two octets of salt.
            // The salt is used to derive the message key and must be unique.
            $salt = substr($bytes, $offset, self::SALT_SIZE);
            $offset += self::SALT_SIZE;

            return new self(
                $version,
                substr($bytes, $offset),
                $symmetric,
                $aead,
                $chunkSize,
                $salt
            );
        }

        return new self($version, substr($bytes, $offset));
    }

    /**
     * Encrypt packet list
     *
     * @param string $key
     * @param PacketListInterface $packetList
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @return self
     */
    public static function encryptPackets(
        string $key,
        PacketListInterface $packetList,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?AeadAlgorithm $aead = null
    ): self {
        Helper::assertSymmetric($symmetric);
        $aeadProtect = $aead instanceof AeadAlgorithm;
        $version = $aeadProtect || Config::useV6Key()
            ? self::VERSION_2 : self::VERSION_1;

        $salt = "";
        $chunkSize = 0;
        if ($aeadProtect) {
            $salt = Random::string(self::SALT_SIZE);
            $chunkSize = Config::getAeadChunkSize();
            $encrypted = self::aeadCrypt(
                self::AEAD_ENCRYPT,
                $key,
                $packetList->encode(),
                "",
                $symmetric,
                $aead,
                $chunkSize,
                $salt
            );
        } else {
            $toHash = implode([
                Helper::generatePrefix($symmetric),
                $packetList->encode(),
                self::MDC_SUFFIX,
            ]);
            $plainText = $toHash . hash(self::HASH_ALGO, $toHash, true);

            $cipher = $symmetric->cipherEngine(Config::CIPHER_MODE);
            $cipher->disablePadding();
            $cipher->setKey($key);
            $cipher->setIV(
                str_repeat(Helper::ZERO_CHAR, $symmetric->blockSize())
            );
            $encrypted = $cipher->encrypt($plainText);
        }

        return new self(
            $version,
            $encrypted,
            $symmetric,
            $aead,
            $chunkSize,
            $salt,
            $packetList
        );
    }

    /**
     * Encrypt packet list with session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param PacketListInterface $packetList
     * @param AeadAlgorithm $aead
     * @return self
     */
    public static function encryptPacketsWithSessionKey(
        SessionKeyInterface $sessionKey,
        PacketListInterface $packetList,
        ?AeadAlgorithm $aead = null
    ): self {
        return self::encryptPackets(
            $sessionKey->getEncryptionKey(),
            $packetList,
            $sessionKey->getSymmetric(),
            $aead
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->version === self::VERSION_2
            ? implode([
                chr($this->version),
                chr($this->symmetric->value),
                chr($this->aead->value),
                chr($this->chunkSize),
                $this->salt,
                $this->encrypted,
            ])
            : implode([chr($this->version), $this->encrypted]);
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
     * {@inheritdoc}
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self {
        if ($this->packetList instanceof PacketListInterface) {
            return $this;
        } else {
            if ($this->aead instanceof AeadAlgorithm) {
                $length = strlen($this->encrypted);
                $data = substr(
                    $this->encrypted,
                    0,
                    $length - $this->aead->tagLength()
                );
                $authTag = substr(
                    $this->encrypted,
                    $length - $this->aead->tagLength()
                );
                $packetBytes = self::aeadCrypt(
                    self::AEAD_DECRYPT,
                    $key,
                    $data,
                    $authTag,
                    $this->symmetric,
                    $this->aead,
                    $this->chunkSize,
                    $this->salt,
                );
            } else {
                $symmetric = $this->symmetric ?? $symmetric;
                $size = $symmetric->blockSize();
                $cipher = $symmetric->cipherEngine(Config::CIPHER_MODE);
                $cipher->disablePadding();
                $cipher->setKey($key);
                $cipher->setIV(str_repeat(Helper::ZERO_CHAR, $size));

                $decrypted = $cipher->decrypt($this->encrypted);
                $digestSize =
                    strlen($decrypted) - HashAlgorithm::Sha1->digestSize();
                $realHash = substr($decrypted, $digestSize);
                $toHash = substr($decrypted, 0, $digestSize);
                if (
                    strcmp($realHash, hash(self::HASH_ALGO, $toHash, true)) !==
                    0
                ) {
                    throw new \RuntimeException("Modification detected.");
                }
                // Remove random prefix & MDC packet
                $packetBytes = substr(
                    $toHash,
                    $size + 2,
                    strlen($toHash) - $size - 4
                );
            }

            return new self(
                $this->version,
                $this->encrypted,
                $this->symmetric,
                $this->aead,
                $this->chunkSize,
                $this->salt,
                PacketList::decode($packetBytes)
            );
        }
    }

    /**
     * AEAD en/decrypt the payload.
     *
     * @param string $fn
     * @param string $key
     * @param string $data
     * @param string $finalChunk
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @param int $chunkSizeByte
     * @param string $salt
     * @return string
     */
    private static function aeadCrypt(
        string $fn,
        string $key,
        string $data,
        string $finalChunk = "",
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        AeadAlgorithm $aead = AeadAlgorithm::Gcm,
        int $chunkSizeByte = 12,
        string $salt = ""
    ): string {
        $chunkSize = 1 << $chunkSizeByte + 6;
        if ($fn === self::AEAD_DECRYPT) {
            $chunkSize += $aead->tagLength();
        }

        $aData = implode([
            chr(
                0xc0 | PacketTag::SymEncryptedIntegrityProtectedData->value
            ),
            chr(self::VERSION_2),
            chr($symmetric->value),
            chr($aead->value),
            chr($chunkSizeByte),
        ]);

        $keySize = $symmetric->keySizeInByte();
        $ivLength = $aead->ivLength();
        $derivedKey = hash_hkdf(
            Config::HKDF_ALGO,
            $key,
            $keySize + $ivLength,
            $aData,
            $salt
        );
        $kek = substr($derivedKey, 0, $keySize);
        $nonce = substr($derivedKey, $keySize, $ivLength);
        // The last 8 bytes of HKDF output are unneeded, but this avoids one copy.
        $nonce = substr_replace(
            $nonce,
            str_repeat(Helper::ZERO_CHAR, 8),
            $ivLength - 8
        );
        $cipher = $aead->cipherEngine($kek, $symmetric);

        $crypted = [];
        for ($index = 0; $index === 0 || strlen($data); ) {
            // Take a chunk of `data`, en/decrypt it,
            // and shift `data` to the next chunk.
            $crypted[] = $cipher->$fn(
                Strings::shift($data, $chunkSize),
                $nonce,
                $aData
            );
            $nonce = substr_replace(
                $nonce,
                pack("N", ++$index),
                $ivLength - 4,
                4
            );
        }

        // For encryption: empty final chunk
        // For decryption: final authentication tag
        $processed = array_sum(
            array_map(static fn ($bytes) => strlen($bytes), $crypted)
        );
        $aDataTag = implode([$aData, str_repeat(Helper::ZERO_CHAR, 8)]);
        $aDataTag = substr_replace(
            $aDataTag,
            pack("N", $processed),
            strlen($aDataTag) - 4,
            4
        );
        $crypted[] = $cipher->$fn($finalChunk, $nonce, $aDataTag);

        return implode($crypted);
    }
}
