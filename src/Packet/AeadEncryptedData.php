<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\{Config, Helper};
use OpenPGP\Enum\{AeadAlgorithm, PacketTag, SymmetricAlgorithm};
use OpenPGP\Type\{
    AeadEncryptedDataPacketInterface,
    PacketListInterface,
    SessionKeyInterface
};
use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Random;

/**
 * AEAD Protected Data Packet class
 *
 * Implementation of the Symmetrically Encrypted Authenticated Encryption with
 * Additional Data (AEAD) Protected Data Packet(Tag 20)
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class AeadEncryptedData extends AbstractPacket implements
    AeadEncryptedDataPacketInterface
{
    use AeadEncryptedDataTrait, EncryptedDataTrait;

    const VERSION = 1;

    private readonly int $version;

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
        private readonly string $encrypted = "",
        private readonly ?PacketListInterface $packetList = null
    ) {
        parent::__construct(PacketTag::AeadEncryptedData);
        $this->version = self::VERSION;
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
            throw new \InvalidArgumentException(
                "Version $version of the AEPD is not supported."
            );
        }

        $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));
        $aead = AeadAlgorithm::from(ord($bytes[$offset++]));
        $chunkSize = ord($bytes[$offset++]);
        $iv = substr($bytes, $offset, $aead->ivLength());
        $offset += $aead->ivLength();
        $encrypted = substr($bytes, $offset);

        return new self($symmetric, $aead, $chunkSize, $iv, $encrypted);
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
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): self {
        Helper::assertSymmetric($symmetric);

        $aead = Config::getPreferredAead();
        $chunkSize = Config::getAeadChunkSize();
        $iv = Random::string($aead->ivLength());

        return new self(
            $symmetric,
            $aead,
            $chunkSize,
            $iv,
            self::crypt(
                self::AEAD_ENCRYPT,
                $key,
                $packetList->encode(),
                "",
                $symmetric,
                $aead,
                $chunkSize,
                $iv
            ),
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
        SessionKeyInterface $sessionKey,
        PacketListInterface $packetList
    ): self {
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
            chr($this->version),
            chr($this->symmetric->value),
            chr($this->aead->value),
            chr($this->chunkSize),
            $this->iv,
            $this->encrypted,
        ]);
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

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): self {
        if ($this->packetList instanceof PacketListInterface) {
            return $this;
        } else {
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

            return new self(
                $this->symmetric,
                $this->aead,
                $this->chunkSize,
                $this->iv,
                $this->encrypted,
                PacketList::decode(
                    self::crypt(
                        self::AEAD_DECRYPT,
                        $key,
                        $data,
                        $authTag,
                        $this->symmetric,
                        $this->aead,
                        $this->chunkSize,
                        $this->iv,
                    )
                )
            );
        }
    }

    /**
     * En/decrypt the payload.
     *
     * @param string $fn
     * @param string $key
     * @param string $data
     * @param string $finalChunk
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @param int $chunkSizeByte
     * @param string $iv
     * @return string
     */
    private static function crypt(
        string $fn,
        string $key,
        string $data,
        string $finalChunk = "",
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        AeadAlgorithm $aead = AeadAlgorithm::Ocb,
        int $chunkSizeByte = 12,
        string $iv = ""
    ): string {
        $dataLength = strlen($data);
        $tagLength = $fn === self::AEAD_ENCRYPT ? 0 : $aead->tagLength();
        $chunkSize = (1 << $chunkSizeByte + 6) + $tagLength;

        $aData = substr_replace(
            str_repeat(Helper::ZERO_CHAR, 13),
            implode([
                chr(0xc0 | PacketTag::AeadEncryptedData->value),
                chr(self::VERSION),
                chr($symmetric->value),
                chr($aead->value),
                chr($chunkSizeByte),
            ]),
            0,
            5
        );
        $ciData = substr($aData, 5, 8);
        $cipher = $aead->cipherEngine($key, $symmetric);

        $crypted = [];
        for ($index = 0; $index === 0 || strlen($data) > 0; ) {
            // Take a chunk of `data`, en/decrypt it,
            // and shift `data` to the next chunk.
            $crypted[] = $cipher->$fn(
                Strings::shift($data, $chunkSize),
                $cipher->getNonce($iv, $ciData),
                $aData
            );

            $aData = substr_replace($aData, pack("N", ++$index), 9, 4);
            $ciData = substr($aData, 5, 8);
        }

        // For encryption: empty final chunk
        // For decryption: final authentication tag
        $processed = $dataLength - $tagLength * ceil($dataLength / $chunkSize);
        $aDataTag = substr_replace(
            str_repeat(Helper::ZERO_CHAR, 21),
            $aData,
            0,
            13
        );
        $aDataTag = substr_replace($aDataTag, pack("N", $processed), 17, 4);
        $crypted[] = $cipher->$fn(
            $finalChunk,
            $cipher->getNonce($iv, $ciData),
            $aDataTag
        );

        return implode($crypted);
    }
}
