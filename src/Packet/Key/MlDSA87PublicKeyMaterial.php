<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{EdDSACurve, HashAlgorithm, MlDSA};
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PublicKey;
use phpseclib4\Crypt\EC\Curves\Ed448;
use phpseclib4\Crypt\EC\Formats\Keys\PKCS8;
use PQCrypto\MLDSA87\VerifyingKey;

/**
 * Post-quantum ML-DSA-87 public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlDSA87PublicKeyMaterial extends EdDSAPublicKeyMaterial
{
    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param VerifyingKey $verifyingKey
     * @return self
     */
    public function __construct(
        PublicKey $publicKey,
        private readonly VerifyingKey $verifyingKey,
    ) {
        parent::__construct($publicKey);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(
        string $bytes,
    ): self {
        $ed = new Ed448();
        $publicKey = EC::loadPublicKeyFormat(
            "PKCS8",
            PKCS8::savePublicKey(
                $ed,
                PKCS8::extractPoint(
                    substr($bytes, 0, EdDSACurve::Ed448->payloadSize()), $ed
                ),
            ),
        );
        $verifyingKey = VerifyingKey::fromBytes(substr($bytes, EdDSACurve::Ed448->payloadSize()));
        return new self($publicKey, $verifyingKey);
    }

    /**
     * Get payload size
     *
     * @return int
     */
    public static function payloadSize(): int
    {
        return EdDSACurve::Ed448->payloadSize()
            + MlDSA::MlDSA87->publicSize();
    }

    /**
     * Get verifying key
     *
     * @return VerifyingKey
     */
    public function getVerifyingKey(): VerifyingKey
    {
        return $this->verifyingKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return MlDSA::MlDSA87->publicSize() * 8;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            'eccParameters' => parent::getParameters(),
            'mldsaPublic' => $this->verifyingKey->bytes(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            parent::toBytes(),
            $this->verifyingKey->bytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature,
    ): bool {
        return false;
    }
}
