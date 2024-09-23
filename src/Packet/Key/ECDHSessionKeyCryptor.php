<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{
    CurveOid,
    HashAlgorithm,
    KekSize,
    KeyAlgorithm,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    KeyPacketInterface,
    SecretKeyPacketInterface,
    SessionKeyCryptorInterface,
    SessionKeyInterface,
};
use phpseclib3\Crypt\{
    DH,
    EC,
};
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;

/**
 * ECDH session key cryptor class.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ECDHSessionKeyCryptor implements SessionKeyCryptorInterface
{
    const ANONYMOUS_SENDER = 'Anonymous Sender    ';
    const PKCS5_BLOCK_SIZE = 8;

    /**
     * Constructor
     *
     * @param BigInteger $ephemeralKey
     * @param string $wrappedKey
     * @param int $pkeskVersion
     * @return self
     */
    public function __construct(
        private readonly BigInteger $ephemeralKey,
        private readonly string $wrappedKey,
        private readonly int $pkeskVersion,
    )
    {
    }

    /**
     * Read encrypted session key from byte string
     *
     * @param string $bytes
     * @param int $pkeskVersion
     * @return self
     */
    public static function fromBytes(string $bytes, int $pkeskVersion): self
    {
        $ephemeralKey = Helper::readMPI($bytes);
        $offset = $ephemeralKey->getLengthInBytes() + 2;
        $length = ord($bytes[$offset++]);
        return new self(
            $ephemeralKey,
            substr($bytes, $offset, $length),
            $pkeskVersion,
        );
    }

    /**
     * Produce cryptor by encrypting session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param KeyPacketInterface $keyPacket
     * @param int $pkeskVersion
     * @return self
     */
    public static function encryptSessionKey(
        SessionKeyInterface $sessionKey,
        KeyPacketInterface $keyPacket,
        int $pkeskVersion,
    ): self
    {
        $keyMaterial = $keyPacket->getKeyMaterial();
        if ($keyMaterial instanceof ECDHPublicKeyMaterial) {
            $privateKey = EC::createKey(
                $keyMaterial->getECKey()->getCurve()
            );
            $sharedSecret = DH::computeSecret(
                $privateKey,
                $keyMaterial->getECKey()->getEncodedCoordinates(),
            );

            $keyWrapper = self::selectKeyWrapper(
                $keyMaterial->getKdfSymmetric()
            );
            $kek = self::ecdhKdf(
                $keyMaterial->getKdfHash(),
                $sharedSecret,
                self::kdfParameter($keyMaterial, $keyPacket->getFingerprint()),
                $keyMaterial->getKdfSymmetric()->keySizeInByte(),
            );
            $wrappedKey = $keyWrapper->wrap(
                $kek, self::pkcs5Encode(implode([
                    $pkeskVersion === self::PKESK_VERSION_3 ?
                        $sessionKey->toBytes() :
                        $sessionKey->getEncryptionKey(),
                    $sessionKey->computeChecksum(),
                ]))
            );

            if ($keyMaterial->getCurveOid() === CurveOid::Curve25519) {
                $ephemeralKey = Helper::bin2BigInt(
                    "\x40" . $privateKey->getEncodedCoordinates()
                );
            }
            else {
                $ephemeralKey = Helper::bin2BigInt(
                    $privateKey->getEncodedCoordinates()
                );
            }
            return new self(
                $ephemeralKey,
                $wrappedKey,
                $pkeskVersion,
            );
        }
        else {
            throw new \InvalidArgumentException(
                'Key material is not instance of ECDH key material.'
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            pack('n', $this->ephemeralKey->getLength()),
            $this->ephemeralKey->toBytes(),
            chr(strlen($this->wrappedKey)),
            $this->wrappedKey,
        ]);
    }

    /**
     * Get ephemeral key
     *
     * @return BigInteger
     */
    public function getEphemeralKey(): BigInteger
    {
        return $this->ephemeralKey;
    }

    /**
     * Get wrapped key
     *
     * @return string
     */
    public function getWrappedKey(): string
    {
        return $this->wrappedKey;
    }

    /**
     * {@inheritdoc}
     */
    public function decryptSessionKey(
        SecretKeyPacketInterface $secretKey
    ): SessionKeyInterface
    {
        return SessionKeyCryptor::sessionKeyFromBytes(
            $this->decrypt($secretKey), $this->pkeskVersion
        );
    }

    /**
     * Decrypt session key by using secret key material
     *
     * @param SecretKeyPacketInterface $secretKey
     * @return string
     */
    protected function decrypt(
        SecretKeyPacketInterface $secretKey
    ): string
    {
        $keyMaterial = $secretKey->getKeyMaterial();
        $publicMaterial = $keyMaterial?->getPublicMaterial();
        if ($keyMaterial instanceof ECDHSecretKeyMaterial &&
            $publicMaterial instanceof ECDHPublicKeyMaterial) {
            if ($publicMaterial->getCurveOid() === CurveOid::Curve25519) {
                $format = 'MontgomeryPublic';
                $key = substr($this->ephemeralKey->toBytes(), 1);
            }
            else {
                $format = 'PKCS8';
                $curve = $publicMaterial->getCurveOid()->getCurve();
                $key = PKCS8::savePublicKey(
                    $curve, PKCS8::extractPoint(
                        "\x00" . $this->ephemeralKey->toBytes(), $curve
                    )
                );
            }
            $publicKey = EC::loadFormat($format, $key);
            $sharedSecret = DH::computeSecret(
                $keyMaterial->getECKey(),
                $publicKey->getEncodedCoordinates(),
            );

            $keyWrapper = self::selectKeyWrapper(
                $publicMaterial->getKdfSymmetric()
            );
            $kek = self::ecdhKdf(
                $publicMaterial->getKdfHash(),
                $sharedSecret,
                self::kdfParameter($publicMaterial, $secretKey->getFingerprint()),
                $publicMaterial->getKdfSymmetric()->keySizeInByte(),
            );
            $key = $keyWrapper->unwrap($kek, $this->wrappedKey);
            return self::pkcs5Decode($key);
        }
        else {
            throw new \InvalidArgumentException(
                'Key material is not instance of ECDH key material.'
            );
        }
    }

    /**
     * Key Derivation Function (RFC 9580)
     *
     * @return string
     */
    private static function ecdhKdf(
        HashAlgorithm $hash,
        string $sharedSecret,
        string $param,
        int $keySize,
    ): string
    {
        $toHash = implode([
            pack('N', 1),
            $sharedSecret,
            $param,
        ]);
        return substr($hash->hash($toHash), 0, $keySize);
    }

    /**
     * Build KDF parameter for ECDH algorithm (RFC 9580)
     *
     * @return string
     */
    private static function kdfParameter(
        ECDHPublicKeyMaterial $keyMaterial, string $fingerprint
    ): string
    {
        $oid = ASN1::encodeOID($keyMaterial->getCurveOid()->value);
        return implode([
            chr(strlen($oid)),
            $oid,
            chr(KeyAlgorithm::Ecdh->value),
            "\x03",
            chr($keyMaterial->getReserved()),
            chr($keyMaterial->getKdfHash()->value),
            chr($keyMaterial->getKdfSymmetric()->value),
            self::ANONYMOUS_SENDER,
            $fingerprint,
        ]);
    }

    /**
     * Add pkcs5 padding to a message
     *
     * @return string
     */
    private static function pkcs5Encode(string $message): string
    {
        $length = strlen($message);
        $n = self::PKCS5_BLOCK_SIZE - ($length % self::PKCS5_BLOCK_SIZE);
        return substr_replace(
            str_repeat(chr($n), $length + $n), $message, 0, $length
        );
    }

    /**
     * Remove pkcs5 padding from a message
     *
     * @return string
     */
    private static function pkcs5Decode(string $message): string
    {
        $len = strlen($message);
        $n = ord($message[$len - 1]);
        if ($len < $n || $n > self::PKCS5_BLOCK_SIZE) {
            throw new \LengthException(
                'Invalid padding length.'
            );
        }
        $ps = substr($message, -$n);
        if (strcmp($ps, str_repeat(chr($n), $n)) !== 0) {
            throw new \RuntimeException(
                'Invalid padding string.'
            );
        }
        return substr($message, 0, -$n);
    }

    private static function selectKeyWrapper(
        SymmetricAlgorithm $symmetric
    ): KeyWrapper
    {
        $keySize = KekSize::from($symmetric->keySizeInByte());
        return match ($symmetric) {
            SymmetricAlgorithm::Camellia128,
            SymmetricAlgorithm::Camellia192,
            SymmetricAlgorithm::Camellia256
            => new CamelliaKeyWrapper($keySize),
            default => new AesKeyWrapper($keySize),
        };
    }
}
