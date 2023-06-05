<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;

/**
 * Signed message interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SignedMessageInterface extends ArmorableInterface
{
    /**
     * Get signature of signed message
     *
     * @return SignatureInterface
     */
    function getSignature(): SignatureInterface;

    /**
     * Verify signatures of signed message
     * Return verification array
     *
     * @param array $verificationKeys
     * @param DateTimeInterface $time
     * @return array
     */
    function verify(array $verificationKeys, ?DateTimeInterface $time = null): array;
}
