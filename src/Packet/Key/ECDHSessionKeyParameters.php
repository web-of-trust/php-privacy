<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Crypt\{DH, EC};
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\{CurveOid, HashAlgorithm, KekSize, KeyAlgorithm};

/**
 * ECDHSessionKeyParameters class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ECDHSessionKeyParameters implements SessionKeyParametersInterface
{
    const ANONYMOUS_SENDER = "\x41\x6e\x6f\x6e\x79\x6d\x6f\x75\x73\x20\x53\x65\x6e\x64\x65\x72\x20\x20\x20\x20";
    const KDF_HEADER = "\x00\x00\x00\x01";
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
     * @return ECDHSessionKeyParameters
     */
    public static function fromBytes(string $bytes): ECDHSessionKeyParameters
    {
        $ephemeralKey = Helper::readMPI($bytes);
        $offset = $ephemeralKey->getLengthInBytes() + 2;
        $length = ord($bytes[$offset++]);
        return new ECDHSessionKeyParameters(
            $ephemeralKey, substr($bytes, $offset, $length)
        );
    }

    /**
     * Produces parameters by encrypting session key
     *
     * @param SessionKey $sessionKey
     * @param ECDHPublicParameters $keyParameters
     * @param string $fingerprint
     * @return ECDHSessionKeyParameters
     */
    public static function produceParameters(
        SessionKey $sessionKey,
        ECDHPublicParameters $keyParameters,
        string $fingerprint
    ): ECDHSessionKeyParameters
    {
        $privateKey = EC::createKey(
            $keyParameters->getCurveOid()->name
        );
        $sharedKey = DH::computeSecret(
            $privateKey, $keyParameters->getPublicKey()
        );

        $keySize = $keyParameters->getKdfSymmetric()->keySizeInByte();
        $keyWrapper = new AesKeyWrapper(KekSize::from($keySize));
        $kek = self::ecdhKdf(
            $keyParameters->getKdfHash(),
            $sharedKey,
            self::ecdhParameter($keyParameters, $fingerprint),
            $keySize
        );
        $wrappedKey = $keyWrapper->wrap(
            $kek, self::pkcs5Encode(implode([
                $sessionKey->encode(),
                $sessionKey->computeChecksum(),
            ]))
        );

        if ($keyParameters->getCurveOid() === CurveOid::Curve25519) {
            $ephemeralKey = Helper::bin2BigInt(
                "\x40" . $privateKey->getPublicKey()->getEncodedCoordinates()
            );
        }
        else {
            $ephemeralKey = Helper::bin2BigInt(
                $privateKey->getPublicKey()->getEncodedCoordinates()
            );
        }
        return new ECDHSessionKeyParameters(
            $ephemeralKey,
            $wrappedKey
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->ephemeralKey->getLength()),
            $this->ephemeralKey->toBytes(),
            chr(strlen($this->wrappedKey)),
            $this->wrappedKey,
        ]);
    }

    /**
     * Gets ephemeral key
     *
     * @return BigInteger
     */
    public function getEphemeralKey(): BigInteger
    {
        return $this->ephemeralKey;
    }

    /**
     * Gets wrapped key
     *
     * @return string
     */
    public function getWrappedKey(): string
    {
        return $this->wrappedKey;
    }

    /**
     * Decrypts session key by using secret key parameters
     *
     * @param ECDHSecretParameters $keyParameters
     * @param string $fingerprint
     * @return SessionKey
     */
    public function decrypt(
        ECDHSecretParameters $keyParameters, string $fingerprint
    ): SessionKey
    {
        $publicParams = $keyParameters->getPublicParams();
        if ($publicParams->getCurveOid() === CurveOid::Curve25519) {
            $format = 'MontgomeryPublic';
            $key = substr($this->ephemeralKey->toBytes(), 1);
        }
        else {
            $format = 'PKCS8';
            $curve = $publicParams->getCurveOid()->getCurve();
            $key = PKCS8::savePublicKey(
                $curve, PKCS8::extractPoint(
                    "\0" . $this->ephemeralKey->toBytes(), $curve
                )
            );
        }
        $publicKey = EC::loadFormat($format, $key);
        $sharedKey = DH::computeSecret(
            $keyParameters->getPrivateKey(), $publicKey
        );

        $keySize = $publicParams->getKdfSymmetric()->keySizeInByte();
        $keyWrapper = new AesKeyWrapper(KekSize::from($keySize));
        $kek = self::ecdhKdf(
            $publicParams->getKdfHash(),
            $sharedKey,
            self::ecdhParameter($publicParams, $fingerprint),
            $keySize
        );
        $key = $keyWrapper->unwrap($kek, $this->wrappedKey);
        return SessionKey::fromBytes(self::pkcs5Decode($key));
    }

    /**
     * Key Derivation Function (RFC 6637)
     * 
     * @return string
     */
    private static function ecdhKdf(
        HashAlgorithm $hash, string $sharedKey, string $param, int $keySize
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
        ECDHPublicParameters $keyParameters, string $fingerprint
    ): string
    {
        $oid = ASN1::encodeOID($keyParameters->getCurveOid()->value);
        return implode([
            chr(strlen($oid)),
            $oid,
            chr(KeyAlgorithm::Ecdh->value),
            "\x3",
            chr($keyParameters->getReserved()),
            chr($keyParameters->getKdfHash()->value),
            chr($keyParameters->getKdfSymmetric()->value),
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
            throw new \LengthException('Invalid padding length.');
        }
        $ps = substr($message, -$n);
        if ($ps !== str_repeat(chr($n), $n)) {
            throw new \UnexpectedValueException('Invalid padding string.');
        }
        return substr($message, 0, -$n);
    }
}
