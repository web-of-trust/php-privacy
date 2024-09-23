<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{
    EdDSACurve,
    HashAlgorithm,
};
use OpenPGP\Type\{
    ECKeyMaterialInterface,
    KeyMaterialInterface,
    PublicKeyMaterialInterface,
};
use phpseclib3\Crypt\Common\{
    AsymmetricKey,
    PublicKey,
};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PublicKey as ECPublicKey;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;

/**
 * EdDSA public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EdDSAPublicKeyMaterial implements ECKeyMaterialInterface, PublicKeyMaterialInterface
{
    /**
     * phpseclib3 EC public key
     */
    private readonly ECPublicKey $publicKey;

    /**
     * Constructor
     *
     * @param string $public
     * @param TwistedEdwards $curve
     * @param ECPublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly string $public,
        TwistedEdwards $curve,
        ?ECPublicKey $publicKey = null,
    )
    {
        if ($publicKey instanceof ECPublicKey) {
            $this->publicKey = $publicKey;
        }
        else {
            $this->publicKey = EC::loadPublicKeyFormat(
                'PKCS8',
                PKCS8::savePublicKey(
                    $curve,
                    PKCS8::extractPoint($public, $curve),
                ),
            );
        }
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param EdDSACurve $curve
     * @return self
     */
    public static function fromBytes(
        string $bytes, EdDSACurve $curve = EdDSACurve::Ed25519
    ): self
    {
        return new self(
            substr($bytes, 0, $curve->payloadSize()),
            $curve->getCurve(),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getECKey(): EC
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return $this->publicKey->getLength();
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicMaterial(): KeyMaterialInterface
    {
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAsymmetricKey(): AsymmetricKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return PKCS8::load($this->publicKey->toString('PKCS8'));
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->public;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature
    ): bool
    {
        return $this->publicKey->verify(
            $hash->hash($message),
            $signature,
        );
    }
}
