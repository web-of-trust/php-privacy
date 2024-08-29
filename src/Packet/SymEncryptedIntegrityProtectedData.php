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
    EncryptedDataPacketInterface,
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
class SymEncryptedIntegrityProtectedData extends AbstractPacket implements EncryptedDataPacketInterface
{
    use EncryptedDataTrait;

    const VERSION_1  = 1;
    const VERSION_2  = 2;
    const HASH_ALGO  = 'sha1';
    const ZERO_CHAR  = "\x00";
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
        if ($aead instanceof AeadAlgorithm && $version !== self::VERSION_2) {
            throw new \UnexpectedValueException(
                "Using AEAD with version {$version} of the SEIPD packet is not allowed."
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
            // - Thirty-two octets of salt. The salt is used to derive the message key and must be unique.
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
            $encrypted = $cryptor->aeadCrypt('encrypt', $key, $packetList->encode());
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
            $cipher->setIV(str_repeat(self::ZERO_CHAR, $symmetric->blockSize()));
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
     * Get version
     *
     * @return int
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * Get symmetric algorithm
     *
     * @return SymmetricAlgorithm
     */
    public function getSymmetricAlgorithm(): SymmetricAlgorithm
    {
        return $this->symmetric;
    }

    /**
     * Get AEAD algorithm
     *
     * @return AeadAlgorithm
     */
    public function getAeadAlgorithm(): ?AeadAlgorithm
    {
        return $this->aead;
    }

    /**
     * Get chunk size byte
     *
     * @return int
     */
    public function getChunkSize(): int
    {
        return $this->chunkSize;
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
                $packetBytes = $this->aeadCrypt(
                    'decrypt', $key, $this->encrypted
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
                $packetBytes = substr($toHash, $size + 2, strlen($toHash) - $size - 4);
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
     * @return string
     */
    protected function aeadCrypt(
        string $fn, string $key, string $data
    ): string
    {
        $dataLength = strlen($data);
        $tagLength = $fn === 'decrypt' ? $this->aead->tagLength() : 0;
        // ((uint64_t)1 << (c + 6))
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
        $iv = substr_replace($iv, $zeroBytes, $ivLength - 8);
        $cipher = $this->aead->cipherEngine($encryptionKey, $this->symmetric);

        $crypted = [];
        $chunk = substr($data, 0, $dataLength - $tagLength);
        for ($chunkIndex = 0; $chunkIndex === 0 || strlen($chunk);) {
            $chunkIndexData = substr($aDataTagBytes, 5, 8);
            $crypted[] = $cipher->$fn(
                substr($chunk, 0, $chunkSize),
                $cipher->getNonce($iv, $chunkIndexData),
                $aData
            );
            // We take a chunk of data, en/decrypt it, and shift `data` to the next chunk.
            $chunk = substr($chunk, $chunkSize);
            $ciBytes = pack('N', ++$chunkIndex);
            $aDataTagBytes = substr_replace(
                $aDataTagBytes, $ciBytes, $tagSize - 4, 4
            );
        }
        $chunkIndexData = substr($aDataTagBytes, 5, 8);
        $bytesProcessed = array_sum(
            array_map(fn ($processed) => strlen($processed), $crypted)
        );
        $processedBytes = pack('N', $bytesProcessed);
        $aDataTagBytes = substr_replace(
            $aDataTagBytes, $processedBytes, $tagSize - 4, 4,
        );

        // After the final chunk, we either encrypt a final, empty data
        // chunk to get the final authentication tag or validate that final
        // authentication tag.
        $crypted[] = $cipher->$fn(
            substr($data, $dataLength - $tagLength, $tagLength),
            $cipher->getNonce($iv, $chunkIndexData),
            $aDataTagBytes
        );
        return implode($crypted);
    }

    private function getAData(): string
    {
        return implode([
            chr(0xc0 | $this->getTag()->value),
            chr($this->version),
            chr($this->symmetric->value),
            chr($this->aead->value),
            chr($this->chunkSize),
        ]);
    }
}
