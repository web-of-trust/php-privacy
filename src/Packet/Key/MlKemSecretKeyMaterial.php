<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{MlKemAlgorithm, MontgomeryCurve};
use OpenPGP\Type\{KeyMaterialInterface, MlKemSecretKeyMaterialInterface};
use ParagonIE\PQCrypto\Compat;
use ParagonIE\PQCrypto\DecapsKeyInterface;
use ParagonIE\PQCrypto\MLKem768\DecapsulationKey as MLKem768DecapKey;
use ParagonIE\PQCrypto\MLKem1024\DecapsulationKey as MLKem1024DecapKey;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\EC\PrivateKey

/**
 * Post-quantum ML-KEM secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class MlKemSecretKeyMaterial extends MontgomerySecretKeyMaterial
    implements MlKemSecretKeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param PrivateKey $privateKey
     * @param DecapsKeyInterface $decapsulationKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        PrivateKey $privateKey,
        private readonly DecapsKeyInterface $decapsulationKey,
        KeyMaterialInterface $publicMaterial,
    ) {
        parent::__construct($privateKey, $publicMaterial);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        KeyMaterialInterface $publicMaterial,
    ): self {
        $curveName = $publicMaterial->getPublicKey()->getCurve();
        $curve = constant(MontgomeryCurve::class . "::" . $curveName);

        $privateKey = EC::loadPrivateKeyFormat(
            "MontgomeryPrivate",
            substr($bytes, 0, $curve->payloadSize()),
        );
        $decapsulationKey = match ($curve) {
            MontgomeryCurve::Curve25519 => new MLKem768DecapKey(
                substr($bytes, $curve->payloadSize())
            ),
            MontgomeryCurve::Curve448 => new MLKem1024DecapKey(
                substr($bytes, $curve->payloadSize())
            ),
        };
        return new self(
            $privateKey, $decapsulationKey, $publicMaterial,
        );
    }

    /**
     * Generate ML-KEM 768 key material
     *
     * @param MontgomeryCurve $curve
     * @return self
     */
    public static function generate(
        MontgomeryCurve $curve = MontgomeryCurve::Curve25519
    ): self {
        $eccKey = EC::loadPrivateKeyFormat(
            "MontgomeryPrivate", $curve->generateSecretKey()
        );

        [$decapsKey, $encapsKey] = match ($curve) {
            MontgomeryCurve::Curve25519 => Compat::mlkem768_keygen(),
            MontgomeryCurve::Curve448 => Compat::mlkem1024_keygen(),
        };
        return new self(
            $eccKey,
            $decapsKey,
            new MlKemPublicKeyMaterial(
                $eccKey->getPublicKey(),
                $encapsKey,
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getDecapsulationKey(): DecapsKeyInterface
    {
        return $this->decapsulationKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            ...parent::getParameters(),
            "decapsulationKey" => $this->decapsulationKey->bytes(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof MlKemPublicKeyMaterial) {
            $curveName = $this->publicMaterial->getPublicKey()->getCurve();
            $curve = constant(MontgomeryCurve::class . "::" . $curveName);
            $encapsKey = $this->publicMaterial->getEncapsulationKey();

            if ($curve === MontgomeryCurve::Curve25519) {
                ['sharedKey' => $ss, 'ciphertext' => $ct] = Compat::mlkem768_encaps($encapsKey);
                $sharedKey = Compat::mlkem768_decaps($this->decapsulationKey, $ct);
            }
            else {
                ['sharedKey' => $ss, 'ciphertext' => $ct] = Compat::mlkem1024_encaps($encapsKey);
                $sharedKey = Compat::mlkem768_decaps($this->decapsulationKey, $ct);
            }

            $isValid = hash_equals($ss, $sharedKey);

            return $isValid && parent::isValid();
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            parent::toBytes(),
            $this->decapsulationKey->bytes(),
        ]);
    }
}
