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

use phpseclib3\Crypt\DH;
use phpseclib3\Crypt\EC;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Enum\KeyAlgorithm;

/**
 * ECDHSessionKeyCryptor class.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ECDHSessionKeyCryptor implements SessionKeyCryptorInterface
{
    const ANONYMOUS_SENDER = "\x41\x6e\x6f\x6e\x79\x6d\x6f\x75\x73\x20\x53\x65\x6e\x64\x65\x72\x20\x20\x20\x20";
    const KDF_HEADER = "\0\0\0\1";
    const PKCS5_BLOCK_SIZE = 8;

    /**
     * Constructor
     *
     * @param ECDHPublicParameters $keyParams
     * @param string $fingerprint
     * @param BigInteger $ephemeralKey
     * @param string $wrappedKey
     * @return self
     */
    public function __construct(
        private ECDHPublicParameters $keyParams,
        private string $fingerprint,
        private BigInteger $ephemeralKey,
        private string $wrappedKey
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(SessionKey $sessionKey): SessionKeyCryptorInterface
    {
        $privateKey = EC::createKey(
            $this->keyParams->getCurveOid()->name
        );
        $publicKey = $privateKey->getPublicKey();
        $sharedKey = DH::computeSecret($privateKey, $this->keyParams->getPublicKey());

        $keySize = $this->keyParams->getKdfSymmetric()->keySizeInByte();
        $keyWrapper = new AesKeyWrapper($keySize);
        $kek = $this->kdf(
            $this->keyParams->getKdfHash(),
            $sharedKey,
            $this->ecdhParam(),
            $keySize
        );
        $key = implode([
            $sessionKey->encode(),
            $sessionKey->computeChecksum(),
        ]);
        $wrappedKey = $keyWrapper->wrap(
            $kek, $this->pkcs5Encode($key)
        );

        return ECDHSessionKeyCryptor(
            $this->keyParams,
            $this->fingerprint,
            Helper::bin2BigInt($publicKey->getEncodedCoordinates()),
            $wrappedKey
        );
    }

    /**
     * Decrypts session key
     * 
     * @param ECDHSecretParameters $keyParams
     * @return SessionKey
     */
    public function decrypt(ECDHSecretParameters $keyParams): SessionKey
    {
        $sharedKey = DH::computeSecret($keyParams->getPrivateKey(), $this->ephemeralKey);
        $publicParams = $keyParams->getPublicParams();
        $keySize = $publicParams->getKdfSymmetric()->keySizeInByte();
        $keyWrapper = new AesKeyWrapper($keySize);
        $kek = $this->kdf(
            $publicParams->getKdfHash(),
            $sharedKey,
            $this->ecdhParam(),
            $keySize
        );
        $key = $keyWrapper->unwrap($kek, $this->wrappedKey);
        return SessionKey::fromBytes($this->pkcs5Decode($key));
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->ephemeralKey->getLength()),
            $this->ephemeralKey->toBytes(true),
            strlen($this->wrappedKey),
            $this->wrappedKey,
        ]);
    }

    /**
     * Key Derivation Function (RFC 6637)
     * 
     * @return string
     */
    private function kdf(
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
     * Build param for ECDH algorithm (RFC 6637)
     * 
     * @return string
     */
    private function ecdhParam(): string
    {
        return implode([
            $this->keyParams->getCurveOid()->value,
            chr(KeyAlgorithm::ECDH->value),
            "\x3",
            chr($this->publicParam->getReserved()->value),
            chr($this->publicParam->getKdfHash()->value),
            chr($this->publicParam->getKdfSymmetric()->value),
            self::ANONYMOUS_SENDER,
            substr($this->fingerprint, 0, 20),
        ]);
    }

    /**
     * Add pkcs5 padding to a message
     * 
     * @param string $message
     * @return string
     */
    private function pkcs5Encode(string $message)
    {
        $n = self::PKCS5_BLOCK_SIZE - strlen($message) % self::PKCS5_BLOCK_SIZE;
        return $message . str_repeat(chr($n), $n);;
    }

    /**
     * Remove pkcs5 padding from a message
     * 
     * @param string $message
     * @return string
     */
    private function pkcs5Decode(string $message)
    {
        $len = strlen($message);
        $n = ord($message[$len - 1]);
        if ($len < $n || $n > self::PKCS5_BLOCK_SIZE) {
            throw new \UnexpectedValueException('Invalid padding length.');
        }
        $ps = substr($message, -$n);
        if ($ps !== str_repeat(chr($n), $n)) {
            throw new \UnexpectedValueException('Invalid padding string.');
        }
        return substr($message, 0, -$n);
    }
}
