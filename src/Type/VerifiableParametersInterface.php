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

use OpenPGP\Enum\HashAlgorithm;

/**
 * Verifiable parameters interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface VerifiableParametersInterface extends KeyParametersInterface
{
    /**
     * Verifies a signature with message
     * 
     * @param HashAlgorithm $hash
     * @param string $message
     * @param string $signature
     * @return bool
     */
    function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature
    ): bool;
}
