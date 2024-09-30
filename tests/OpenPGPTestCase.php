<?php declare(strict_types=1);

namespace OpenPGP\Tests;

use Faker\Factory as FakerFactory;
use PHPUnit\Framework\TestCase;

/**
 * Base class for all OpenPGP test cases.
 */
abstract class OpenPGPTestCase extends TestCase
{
    protected $faker;

    protected function setUp(): void
    {
        $this->faker = FakerFactory::create();
    }
}
