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
 * Signable parameters interface
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SignableParametersInterface extends KeyParametersInterface
{
    /**
     * Signs a message and returns signature
     * 
     * @param HashAlgorithm $hash
     * @param string $message
     * @return string
     */
    function sign(HashAlgorithm $hash, string $message): string;
}
