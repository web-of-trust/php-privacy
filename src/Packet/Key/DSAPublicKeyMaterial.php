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
use phpseclib4\Crypt\DSA;
use phpseclib4\Crypt\DSA\PublicKey as DSAPublicKey;

/**
 * DSA public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class DSAPublicKeyMaterial implements PublicKeyMaterialInterface
{
    private readonly array $parameters;

    /**
     * Constructor
     *
     * @param DSAPublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly DSAPublicKey $publicKey,
    ) {
        $this->parameters = $publicKey->toArray();
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $prime = Helper::readMPI($bytes);

        $offset = $prime->getLengthInBytes() + 2;
        $order = Helper::readMPI(substr($bytes, $offset));

        $offset += $order->getLengthInBytes() + 2;
        $generator = Helper::readMPI(substr($bytes, $offset));

        $offset += $generator->getLengthInBytes() + 2;
        $exponent = Helper::readMPI(substr($bytes, $offset));

        return new self(DSA::loadPublicKey([
            "y" => $exponent,
            "p" => $prime,
            "q" => $order,
            "g" => $generator,
        ]));
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return $this->parameters["p"]->getLength();
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
    public function getParameters(): array
    {
        return $this->publicKey->toArray();
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
            pack("n", $this->parameters["p"]->getLength()),
            $this->parameters["p"]->toBytes(),
            pack("n", $this->parameters["q"]->getLength()),
            $this->parameters["q"]->toBytes(),
            pack("n", $this->parameters["g"]->getLength()),
            $this->parameters["g"]->toBytes(),
            pack("n", $this->parameters["y"]->getLength()),
            $this->parameters["y"]->toBytes(),
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
        $r = Helper::readMPI($signature);
        $s = Helper::readMPI(substr($signature, $r->getLengthInBytes() + 2));
        return $this->publicKey
            ->withSignatureFormat("Raw")
            ->withHash(strtolower(str_replace("_", "-", $hash->name)))
            ->verify($message, ["r" => $r, "s" => $s]);
    }
}
