<?php declare(strict_types=1);

namespace OpenPGP\Tests;

use Faker\Factory as FakerFactory;
use Monolog\Level;
use Monolog\Logger;
use Monolog\Handler\ErrorLogHandler;
use OpenPGP\Common\Config;
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

        $log = new Logger('PHP Privacy');
        $log->pushHandler(
            new ErrorLogHandler(ErrorLogHandler::OPERATING_SYSTEM, Level::Error)
        );
        Config::setLogger($log);
    }
}
