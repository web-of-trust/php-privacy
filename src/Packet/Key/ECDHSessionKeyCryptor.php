<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Crypt\{
    DH,
    EC,
};
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\{
    CurveOid,
    HashAlgorithm,
    KekSize,
    KeyAlgorithm,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    KeyMaterialInterface,
    SecretKeyPacketInterface,
    SessionKeyCryptorInterface,
    SessionKeyInterface,
};

/**
 * ECDH session key cryptor class.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ECDHSessionKeyCryptor implements SessionKeyCryptorInterface
{
    const ANONYMOUS_SENDER = "\x41\x6e\x6f\x6e\x79\x6d\x6f\x75\x73\x20\x53\x65\x6e\x64\x65\x72\x20\x20\x20\x20";
    const KDF_HEADER       = "\x00\x00\x00\x01";
    const PKCS5_BLOCK_SIZE = 8;

    /**
     * Constructor
     *
     * @param BigInteger $ephemeralKey
     * @param string $wrappedKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $ephemeralKey,
        private readonly string $wrappedKey
    )
    {
    }

    /**
     * Read encrypted session key from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $ephemeralKey = Helper::readMPI($bytes);
        $offset = $ephemeralKey->getLengthInBytes() + 2;
        $length = ord($bytes[$offset++]);
        return new self(
            $ephemeralKey, substr($bytes, $offset, $length)
        );
    }

    /**
     * Produce cryptor by encrypting session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param KeyMaterialInterface $keyMaterial
     * @param string $fingerprint
     * @return self
     */
    public static function encryptSessionKey(
        SessionKeyInterface $sessionKey,
        KeyMaterialInterface $keyMaterial,
        string $fingerprint
    ): self
    {
        if ($keyMaterial instanceof ECDHPublicKeyMaterial) {
            $privateKey = EC::createKey(
                $keyMaterial->getCurveOid()->name
            );
            $sharedKey = DH::computeSecret(
                $privateKey,
                $keyMaterial->getECPublicKey()->getEncodedCoordinates()
            );

            $keyWrapper = self::selectKeyWrapper(
                $keyMaterial->getKdfSymmetric()
            );
            $kek = self::ecdhKdf(
                $keyMaterial->getKdfHash(),
                $sharedKey,
                self::ecdhParameter($keyMaterial, $fingerprint),
                $keyMaterial->getKdfSymmetric()->keySizeInByte()
            );
            $wrappedKey = $keyWrapper->wrap(
                $kek, self::pkcs5Encode(implode([
                    $sessionKey->toBytes(),
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
                $wrappedKey
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
        return SessionKey::fromBytes($this->decrypt(
            $secretKey->getKeyMaterial(),
            $secretKey->getFingerprint()
        ));
    }

    /**
     * Decrypt session key by using secret key material
     *
     * @param KeyMaterialInterface $keyMaterial
     * @param string $fingerprint
     * @return string
     */
    public function decrypt(
        KeyMaterialInterface $keyMaterial, string $fingerprint
    ): string
    {
        $publicMaterial = $keyMaterial->getPublicMaterial();
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
            $sharedKey = DH::computeSecret(
                $keyMaterial->getECPrivateKey(),
                $publicKey->getEncodedCoordinates()
            );

            $keyWrapper = self::selectKeyWrapper(
                $publicMaterial->getKdfSymmetric()
            );
            $kek = self::ecdhKdf(
                $publicMaterial->getKdfHash(),
                $sharedKey,
                self::ecdhParameter($publicMaterial, $fingerprint),
                $publicMaterial->getKdfSymmetric()->keySizeInByte()
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
     * Key Derivation Function (RFC 6637)
     * 
     * @return string
     */
    private static function ecdhKdf(
        HashAlgorithm $hash,
        string $sharedKey,
        string $param,
        int $keySize
    ): string
    {
        $toHash = implode([
            self::KDF_HEADER,
            $sharedKey,
            $param,
        ]);
        $hash = hash(strtolower($hash->name), $toHash, true);
        return substr($hash, 0, $keySize);
    }

    /**
     * Build parameter for ECDH algorithm (RFC 6637)
     * 
     * @return string
     */
    private static function ecdhParameter(
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
            substr($fingerprint, 0, 20),
        ]);
    }

    /**
     * Add pkcs5 padding to a message
     * 
     * @return string
     */
    private static function pkcs5Encode(string $message)
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
    private static function pkcs5Decode(string $message)
    {
        $len = strlen($message);
        $n = ord($message[$len - 1]);
        if ($len < $n || $n > self::PKCS5_BLOCK_SIZE) {
            throw new \LengthException(
                'Invalid padding length.'
            );
        }
        $ps = substr($message, -$n);
        if ($ps !== str_repeat(chr($n), $n)) {
            throw new \UnexpectedValueException(
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
