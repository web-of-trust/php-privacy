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

use OpenPGP\Enum\HashAlgorithm;

/**
 * DSA signing trait
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
trait DSASigningTrait
{
    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->getPrivateKey()
            ->withSignatureFormat('Raw')
            ->withHash($hash->name)
            ->sign($message);
        return implode([
            pack('n', $signature['r']->getLength()),
            $signature['r']->toBytes(),
            pack('n', $signature['s']->getLength()),
            $signature['s']->toBytes(),
        ]);
    }
}
