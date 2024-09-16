<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\{
    Config,
    Helper,
};
use OpenPGP\Enum\{
    AeadAlgorithm,
    HashAlgorithm,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    AeadEncryptedDataPacketInterface,
    PacketListInterface,
    SessionKeyInterface,
};
use phpseclib3\Crypt\Random;

/**
 * Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
 *
 * See RFC 9580, section 5.13.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SymEncryptedIntegrityProtectedData extends AbstractPacket implements AeadEncryptedDataPacketInterface
{
    use AeadEncryptedDataTrait, EncryptedDataTrait;

    const VERSION_1  = 1;
    const VERSION_2  = 2;
    const HASH_ALGO  = 'sha1';
    const MDC_SUFFIX = "\xd3\x14";
    const SALT_SIZE  = 32;

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
        private readonly SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        private readonly ?AeadAlgorithm $aead = null,
        private readonly int $chunkSize = 12,
        private readonly string $salt = '',
        private readonly ?PacketListInterface $packetList = null
    )
    {
        parent::__construct(PacketTag::SymEncryptedIntegrityProtectedData);
        if ($version !== self::VERSION_1 && $version !== self::VERSION_2) {
            throw new \UnexpectedValueException(
                "Version $version of the SEIPD packet is unsupported.",
            );
        }
        $isV2 = $version === self::VERSION_2;
        if ($isV2) {
            self::validateSymmetric($symmetric);
        }
        if ($aead instanceof AeadAlgorithm && !$isV2) {
            throw new \UnexpectedValueException(
                "Using AEAD with v{$version} SEIPD packet is not allowed."
            );
        }
        if (!empty($salt) && strlen($salt) !== self::SALT_SIZE) {
            throw new \LengthException(
                'Salt size must be ' . self::SALT_SIZE . ' bytes.'
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
            $symmetric = SymmetricAlgorithm::from(
                ord($bytes[$offset++])
            );
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
                $salt,
            );
        }

        return new self(
            $version,
            substr($bytes, $offset),
        );
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
        ?AeadAlgorithm $aead = null,
    ): self
    {
        $aeadProtect = $aead instanceof AeadAlgorithm;
        $version = $aeadProtect ? self::VERSION_2 : self::VERSION_1;
        self::validateSymmetric($symmetric);

        $salt = '';
        $chunkSize = 0;
        if ($aeadProtect) {
            $salt = Random::string(self::SALT_SIZE);
            $chunkSize = Config::getAeadChunkSize();
            $cryptor = new self(
                $version,
                '',
                $symmetric,
                $aead,
                $chunkSize,
                $salt,
            );
            $encrypted = $cryptor->aeadCrypt(
                self::AEAD_ENCRYPT, $key, $packetList->encode()
            );
        }
        else {
            $toHash = implode([
                Helper::generatePrefix($symmetric),
                $packetList->encode(),
                self::MDC_SUFFIX,
            ]);
            $plainText = $toHash . hash(self::HASH_ALGO, $toHash, true);

            $cipher = $symmetric->cipherEngine(Config::CIPHER_MODE);
            $cipher->setKey($key);
            $cipher->setIV(
                str_repeat(self::ZERO_CHAR, $symmetric->blockSize())
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
            $packetList,
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
        ?AeadAlgorithm $aead = null,
    ): self
    {
        return self::encryptPackets(
            $sessionKey->getEncryptionKey(),
            $packetList,
            $sessionKey->getSymmetric(),
            $aead,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        if ($this->version === self::VERSION_2) {
            return implode([
                chr($this->version),
                chr($this->symmetric->value),
                chr($this->aead->value),
                chr($this->chunkSize),
                $this->salt,
                $this->encrypted,
            ]);
        }
        else {
            return implode([
                chr($this->version),
                $this->encrypted,
            ]);
        }
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
    ): self
    {
        if ($this->packetList instanceof PacketListInterface) {
            return $this;
        }
        else {
            $this->getLogger()->debug(
                'Decrypt the encrypted data contained in the packet.'
            );
            if ($this->aead instanceof AeadAlgorithm) {
                $length = strlen($this->encrypted);
                $data = substr(
                    $this->encrypted, 0, $length - $this->aead->tagLength()
                );
                $authTag = substr(
                    $this->encrypted, $length - $this->aead->tagLength()
                );
                $packetBytes = $this->aeadCrypt(
                    self::AEAD_DECRYPT, $key, $data, $authTag
                );
            }
            else {
                $size = $symmetric->blockSize();
                $cipher = $symmetric->cipherEngine(Config::CIPHER_MODE);
                $cipher->setKey($key);
                $cipher->setIV(str_repeat(self::ZERO_CHAR, $size));

                $decrypted = $cipher->decrypt($this->encrypted);
                $digestSize = strlen($decrypted) - HashAlgorithm::Sha1->digestSize();
                $realHash = substr($decrypted, $digestSize);
                $toHash = substr($decrypted, 0, $digestSize);
                if (strcmp($realHash, hash(self::HASH_ALGO, $toHash, true)) !== 0) {
                    throw new \UnexpectedValueException(
                        'Modification detected.'
                    );
                }
                // Remove random prefix & MDC packet
                $packetBytes = substr(
                    $toHash, $size + 2, strlen($toHash) - $size - 4
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
     * @param string $fn - Whether to encrypt or decrypt
     * @param string $key - The session key used to en/decrypt the payload
     * @param string $data - The data to en/decrypt
     * @param string $finalChunk - For encryption: empty final chunk; for decryption: final authentication tag
     * @return string
     */
    private function aeadCrypt(
        string $fn, string $key, string $data, string $finalChunk = ''
    ): string
    {
        $tagLength = $fn === self::AEAD_DECRYPT ? $this->aead->tagLength() : 0;
        // chunkSize = (uint32_t) 1 << (c + 6)
        $chunkSize = (1 << ($this->chunkSize + 6)) + $tagLength;

        $aData = $this->getAData();
        $zeroBytes = str_repeat(self::ZERO_CHAR, 8);

        $aDataTagBytes = implode([
            $aData,
            $zeroBytes,
        ]);
        $tagSize = strlen($aDataTagBytes);

        $keySize = $this->symmetric->keySizeInByte();
        $ivLength = $this->aead->ivLength();
        $derivedKey = hash_hkdf(
            Config::HKDF_ALGO, $key, $keySize + $ivLength, $aData, $this->salt
        );
        $encryptionKey = substr($derivedKey, 0, $keySize);
        $iv = substr($derivedKey, $keySize, $keySize + $ivLength);
        // The last 8 bytes of HKDF output are unneeded, but this avoids one copy.
        $iv = substr_replace($iv, $zeroBytes, $ivLength - 8);
        $cipher = $this->aead->cipherEngine($encryptionKey, $this->symmetric);

        $crypted = [];
        $ciBytes = substr($aDataTagBytes, 5, 8);
        for ($chunkIndex = 0; $chunkIndex === 0 || strlen($data);) {
            // Take a chunk of data, en/decrypt it, and shift `data` to the next chunk.
            $crypted[] = $cipher->$fn(
                substr($data, 0, $chunkSize),
                $cipher->getNonce($iv, $ciBytes),
                $aData
            );
            $data = substr($data, $chunkSize);
            $aDataTagBytes = substr_replace(
                $aDataTagBytes, pack('N', ++$chunkIndex), $tagSize - 4, 4
            );
            $ciBytes = substr($aDataTagBytes, 5, 8);
        }
        $processed = array_sum(
            array_map(static fn ($bytes) => strlen($bytes), $crypted)
        );
        $aDataTagBytes = substr_replace(
            $aDataTagBytes, pack('N', $processed), $tagSize - 4, 4
        );

        // After the final chunk, we either encrypt a final, empty data
        // chunk to get the final authentication tag or validate that final
        // authentication tag.
        $crypted[] = $cipher->$fn(
            $finalChunk,
            $cipher->getNonce($iv, $ciBytes),
            $aDataTagBytes
        );
        return implode($crypted);
    }
}
