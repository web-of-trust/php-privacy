<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\Config;
use OpenPGP\Enum\{
    AeadAlgorithm,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    EncryptedDataPacketInterface,
    SessionKeyInterface,
    PacketListInterface,
};
use phpseclib3\Crypt\Random;

/**
 * AEAD Protected Data Packet class
 * 
 * Implementation of the Symmetrically Encrypted Authenticated Encryption with
 * Additional Data (AEAD) Protected Data Packet(Tag 20)
 * See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis#name-aead-encrypted-data-packet-
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class AeadEncryptedData extends AbstractPacket implements EncryptedDataPacketInterface
{
    use EncryptedDataTrait;

    const VERSION   = 1;
    const ZERO_CHAR = "\x00";

    /**
     * Constructor
     *
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @param int $chunkSize
     * @param string $iv
     * @param string $encrypted
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(
        private readonly SymmetricAlgorithm $symmetric,
        private readonly AeadAlgorithm $aead,
        private readonly int $chunkSize,
        private readonly string $iv,
        private readonly string $encrypted = '',
        private readonly ?PacketListInterface $packetList = null
    )
    {
        parent::__construct(PacketTag::AeadEncryptedData);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        // A one-octet version number.
        // The only currently defined version is 1.
        $version = ord($bytes[$offset++]);
        if ($version !== self::VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the AEAD-encrypted data packet is not supported.",
          );
        }

        $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));
        $aead = AeadAlgorithm::from(ord($bytes[$offset++]));
        $chunkSize = ord($bytes[$offset++]);
        $iv = substr($bytes, $offset, $aead->ivLength());
        $offset += $aead->ivLength();
        $encrypted = substr($bytes, $offset);

        return new self(
            $symmetric,
            $aead,
            $chunkSize,
            $iv,
            $encrypted
        );
    }

    /**
     * Encrypt packet list
     *
     * @param string $key
     * @param PacketListInterface $packetList
     * @param SymmetricAlgorithm $symmetric
     * @return self
     */
    public static function encryptPackets(
        string $key,
        PacketListInterface $packetList,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        $aead = Config::getPreferredAead();
        $chunkSize = Config::getAeadChunkSize();
        $iv = Random::string($aead->ivLength());

        $encryptor = new self(
            $symmetric,
            $aead,
            $chunkSize,
            $iv
        );

        return new self(
            $symmetric,
            $aead,
            $chunkSize,
            $iv,
            $encryptor->crypt('encrypt', $key, $packetList->encode()),
            $packetList
        );
    }

    /**
     * Encrypt packet list with session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function encryptPacketsWithSessionKey(
        SessionKeyInterface $sessionKey, PacketListInterface $packetList
    ): self
    {
        return self::encryptPackets(
            $sessionKey->getEncryptionKey(),
            $packetList,
            $sessionKey->getSymmetric()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr(self::VERSION),
            chr($this->symmetric->value),
            chr($this->aead->value),
            chr($this->chunkSize),
            $this->iv,
            $this->encrypted,
        ]);
    }

    /**
     * Get version
     *
     * @return int
     */
    public function getVersion(): int
    {
        return self::VERSION;
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
    public function getAeadAlgorithm(): AeadAlgorithm
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
     * Get initialization vector
     * 
     * @return string
     */
    public function getIV(): string
    {
        return $this->iv;
    }

    private function getAAData(): string
    {
        return implode([
            chr(0xc0 | $this->getTag()->value),
            chr(self::VERSION),
            chr($this->symmetric->value),
            chr($this->aead->value),
            chr($this->chunkSize),
        ]);
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
            $length = strlen($this->encrypted);
            $data = substr(
                $this->encrypted, 0, $length - $this->aead->tagLength()
            );
            $authTag = substr(
                $this->encrypted, $length - $this->aead->tagLength()
            );

            return new self(
                $this->symmetric,
                $this->aead,
                $this->chunkSize,
                $this->iv,
                $this->encrypted,
                PacketList::decode(
                    $this->crypt('decrypt', $key, $data, $authTag)
                )
            );
        }
    }

    /**
     * En/decrypt the payload.
     * 
     * @param string $fn - Whether to encrypt or decrypt
     * @param string $key - The session key used to en/decrypt the payload
     * @param string $data - The data to en/decrypt
     * @param string $finalChunk - For encryption: empty final chunk; for decryption: final authentication tag
     * @return string
     */
    protected function crypt(
        string $fn, string $key, string $data, string $finalChunk = ''
    ): string
    {
        $cipher = $this->aead->cipherEngine($key, $this->symmetric);

        $dataLength = strlen($data);
        $tagLength = $fn === 'decrypt' ? $this->aead->tagLength() : 0;
        $chunkSize = 2 ** ($this->chunkSize + 6) + $tagLength; // ((uint64_t)1 << (c + 6))

        $zeroBuffer = str_repeat(self::ZERO_CHAR, 21);
        $adataBuffer = substr($zeroBuffer, 0, 13);
        $adataTagBuffer = $zeroBuffer;

        $aaData = $this->getAAData();
        $adataBuffer = substr_replace($adataBuffer, $aaData, 0, strlen($aaData));

        $adataTagBuffer = substr_replace($adataTagBuffer, $aaData, 0, strlen($aaData));
        $cryptedBytes = pack('N', $dataLength - $tagLength * (int) ceil($dataLength / $chunkSize));
        $adataTagBuffer = substr_replace($adataTagBuffer, $cryptedBytes, 13 + 4, strlen($cryptedBytes));

        $crypted = [];
        for ($chunkIndex = 0; $chunkIndex === 0 || strlen($data);) {
            $chunkIndexData = substr($adataTagBuffer, 5, 8);
            $crypted[] = $cipher->$fn(
                substr($data, 0, $chunkSize),
                $cipher->getNonce($this->iv, $chunkIndexData),
                $adataBuffer
            );
            // We take a chunk of data, en/decrypt it, and shift `data` to the next chunk.
            $data = substr($data, $chunkSize);
            $ciBytes = pack('N', ++$chunkIndex);
            $adataTagBuffer = substr_replace(
                $adataTagBuffer, $ciBytes, 5 + 4, strlen($ciBytes)
            );
        }

        // After the final chunk, we either encrypt a final, empty data
        // chunk to get the final authentication tag or validate that final
        // authentication tag.
        $chunkIndexData = substr($adataTagBuffer, 5, 8);
        $crypted[] = $cipher->$fn(
            $finalChunk,
            $cipher->getNonce($this->iv, $chunkIndexData),
            $adataTagBuffer
        );
        return implode($crypted);
    }
}
