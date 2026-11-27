<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Type\{KeyMaterialInterface, PublicKeyMaterialInterface};
use phpseclib4\Crypt\Common\PublicKey;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\PublicKey as RSAPublicKey;
m
/**
 * RSA public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class RSAPublicKeyMaterial implements PublicKeyMaterialInterface
{
    private readonly array $parameters;

    /**
     * Constructor
     *
     * @param RSAPublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly RSAPublicKey $publicKey,
    ) {
        $this->parameters = $publicKey->toArray();
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $modulus = Helper::readMPI($bytes);
        $exponent = Helper::readMPI(substr($bytes, $modulus->getLengthInBytes() + 2));
        return new self(RSA::loadPublicKey([
            "modulus" => $modulus,
            "publicExponent" => $exponent,
        ]));
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
    public function getPublicMaterial(): KeyMaterialInterface
    {
        return $this;
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
    public function getParameters(): array
    {
        return $this->parameters;
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
        return implode([
            pack("n", $this->parameters["n"]->getLength()),
            $this->parameters["n"]->toBytes(),
            pack("n", $this->parameters["e"]->getLength()),
            $this->parameters["e"]->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     *
     * The signature is stored as an MPI, which carries no leading zero
     * octets (RFC 9580, section 3.2). PKCS#1 v1.5 verification expects
     * the signature as an octet string of the length of the modulus
     * (RFC 8017, section 8.2.2), so it is left-padded with zero octets.
     * A value longer than the modulus is rejected.
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature,
    ): bool {
        if (strlen($signature) < 2) {
            return false;
        }
        $length = Helper::bit2ByteLength(Helper::bytesToShort($signature));
        $value = substr($signature, 2, $length);
        $modulusLength = $this->parameters["n"]->getLengthInBytes();
        if ($length > $modulusLength || strlen($value) !== $length) {
            return false;
        }
        $value = str_pad($value, $modulusLength, "\0", STR_PAD_LEFT);
        return $this->publicKey
            ->withHash(strtolower(str_replace("_", "-", $hash->name)))
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->verify($message, $value);
    }
}
