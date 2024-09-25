<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\MontgomeryCurve;
use OpenPGP\Type\{
    SecretKeyPacketInterface,
    SessionKeyCryptorInterface,
    SessionKeyInterface,
};
use phpseclib3\Crypt\{
    DH,
    EC,
};

/**
 * Montgomery session key cryptor class.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MontgomerySessionKeyCryptor implements SessionKeyCryptorInterface
{
    /**
     * Constructor
     *
     * @param string $ephemeralKey
     * @param string $wrappedKey
     * @param MontgomeryCurve $curve
     * @return self
     */
    public function __construct(
        private readonly string $ephemeralKey,
        private readonly string $wrappedKey,
        private readonly MontgomeryCurve $curve = MontgomeryCurve::Curve25519,
    )
    {
    }

    /**
     * Read encrypted session key from byte string
     *
     * @param string $bytes
     * @param MontgomeryCurve $curve
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        MontgomeryCurve $curve = MontgomeryCurve::Curve25519,
    ): self
    {
        return new self(
            substr($bytes, 0, $curve->payloadSize()),
            substr(
                $bytes,
                $curve->payloadSize() + 1,
                ord($bytes[$curve->payloadSize()]),
            ),
            $curve,
        );
    }

    /**
     * Produce cryptor by encrypting session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param EC $publicKey
     * @param MontgomeryCurve $curve
     * @return self
     */
    public static function encryptSessionKey(
        SessionKeyInterface $sessionKey,
        EC $publicKey,
        MontgomeryCurve $curve = MontgomeryCurve::Curve25519,
    ): self
    {
        if ($sessionKey->getSymmetric() !== $curve->symmetricAlgorithm()) {
            throw new \InvalidArgumentException(
                'Symmetric algorithm of the session key mismatch!'
            );
        }
        $privateKey = EC::createKey($publicKey->getCurve());
        $ephemeralKey = $privateKey->getPublicKey()->getEncodedCoordinates();

        $kek = hash_hkdf(
            $curve->hashAlgorithm(),
            implode([
                $ephemeralKey,
                $publicKey->getEncodedCoordinates(),
                DH::computeSecret(
                    $privateKey,
                    $publicKey->getEncodedCoordinates(),
                ),
            ]),
            $curve->kekSize()->value,
            $curve->hkdfInfo(),
        );
        $keyWrapper = new AesKeyWrapper(
            $curve->kekSize()
        );

        return new self(
            $ephemeralKey,
            $keyWrapper->wrap(
                $kek,
                $sessionKey->getEncryptionKey(),
            ),
            $curve,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            $this->ephemeralKey,
            chr(strlen($this->wrappedKey)),
            $this->wrappedKey,
        ]);
    }

    /**
     * Get ephemeral key
     *
     * @return string
     */
    public function getEphemeralKey(): string
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
        return new SessionKey(
            $this->decrypt(
                $secretKey->getECKeyMaterial()->getECKey(),
            ),
            $this->curve->symmetricAlgorithm(),
        );
    }

    /**
     * Decrypt session key by using private key
     *
     * @param EC $privateKey
     * @return string
     */
    private function decrypt(EC $privateKey): string
    {
        $kek = hash_hkdf(
            $this->curve->hashAlgorithm(),
            implode([
                $this->ephemeralKey,
                $privateKey->getEncodedCoordinates(),
                DH::computeSecret(
                    $privateKey,
                    EC::loadFormat(
                        'MontgomeryPublic', $this->ephemeralKey
                    )->getEncodedCoordinates(),
                ),
            ]),
            $this->curve->kekSize()->value,
            $this->curve->hkdfInfo(),
        );
        $keyWrapper = new AesKeyWrapper(
            $this->curve->kekSize()
        );
        return $keyWrapper->unwrap($kek, $this->wrappedKey);
    }
}
