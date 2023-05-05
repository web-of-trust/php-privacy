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
use OpenPGP\Helper;

/**
 * DSA verifying trait
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
trait DSAVerifyingTrait
{
    /**
     * {@inheritdoc}
     */
    public function verify(
        string $message,
        HashAlgorithm $hash,
        string $signature
    ): bool
    {
        $r = Helper::readMPI($signature);
        $s = Helper::readMPI(substr($signature, $r->getLengthInBytes() + 2));
        return $this->getPublicKey()->withSignatureFormat('Raw')->withHash($hash->name)->verify($message, [$r, $s]);
    }
}
