<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{EdDSACurve, HashAlgorithm, MlDSA};
use phpseclib4\Crypt\EC\Curves\Ed448;
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
     * PQCrypto ML-DSA-87 verifying key
     */
    private readonly VerifyingKey $verifyingKey;

    /**
     * Constructor
     *
     * @param string $eccPublic
     * @param string $mldsaPublic
     * @return self
     */
    public function __construct(
        string $eccPublic,
        private readonly string $mldsaPublic,
    ) {
        parent::__construct($eccPublic, new Ed448());
        $this->verifyingKey = VerifyingKey::fromBytes($mldsaPublic);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param EdDSACurve $curve
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        EdDSACurve $curve = EdDSACurve::Ed448,
    ): self {
        return new self(
            substr($bytes, 0, EdDSACurve::Ed448->payloadSize()),
            substr($bytes, EdDSACurve::Ed448->payloadSize()),
        );
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
            'mldsaPublic' => $this->mldsaPublic,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            parent::toBytes(),
            $this->mldsaPublic,
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
