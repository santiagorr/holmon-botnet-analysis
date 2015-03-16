-- phpMyAdmin SQL Dump
-- version 3.4.11.1deb2
-- http://www.phpmyadmin.net
--
-- Servidor: localhost
-- Tiempo de generación: 15-07-2014 a las 11:04:13
-- Versión del servidor: 5.5.37
-- Versión de PHP: 5.4.4-14+deb7u9

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Base de datos: `holmonflows`
--
CREATE DATABASE IF NOT EXISTS `holmonflows` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE `holmonflows`;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `dhcp`
--

CREATE TABLE IF NOT EXISTS `dhcp` (
  `id` bigint(20) NOT NULL,
  `os` varchar(250) DEFAULT NULL,
  `vc` varchar(250) DEFAULT NULL,
  `ros` varchar(250) DEFAULT NULL,
  `rvc` varchar(250) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `dns`
--

CREATE TABLE IF NOT EXISTS `dns` (
  `id` bigint(20) NOT NULL,
  `tid` mediumint(8) unsigned DEFAULT NULL,
  `qr` tinyint(3) unsigned DEFAULT NULL,
  `type` mediumint(8) unsigned DEFAULT NULL,
  `auth` tinyint(3) unsigned DEFAULT NULL,
  `nx` tinyint(3) unsigned DEFAULT NULL,
  `section` tinyint(3) unsigned DEFAULT NULL,
  `ttl` int(10) unsigned DEFAULT NULL,
  `rrname` varchar(256) DEFAULT NULL,
  `rrval` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `flows`
--

CREATE TABLE IF NOT EXISTS `flows` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `srcip4` int(10) unsigned DEFAULT NULL,
  `dstip4` int(10) unsigned DEFAULT NULL,
  `srcport` mediumint(8) unsigned DEFAULT NULL,
  `dstport` mediumint(8) unsigned DEFAULT NULL,
  `protocol` tinyint(3) unsigned DEFAULT NULL,
  `vlan` mediumint(8) unsigned DEFAULT NULL,
  `srcip6` binary(16) DEFAULT NULL,
  `dstip6` binary(16) DEFAULT NULL,
  `flowStartMilliseconds` datetime DEFAULT NULL,
  `flowEndMilliseconds` datetime DEFAULT NULL,
  `octetTotalCount` bigint(20) unsigned DEFAULT NULL,
  `reverseOctetTotalCount` bigint(20) unsigned DEFAULT NULL,
  `packetTotalCount` bigint(20) unsigned DEFAULT NULL,
  `reversePacketTotalCount` bigint(20) unsigned DEFAULT NULL,
  `silkAppLabel` mediumint(8) unsigned DEFAULT NULL,
  `flowEndReason` tinyint(3) unsigned DEFAULT NULL,
  `ObservationDomain` int(10) unsigned DEFAULT NULL,
  `flowAttributes` mediumint(9) DEFAULT NULL,
  `reverseFlowAttributes` mediumint(9) DEFAULT NULL,
  `ingressInterface` mediumint(9) DEFAULT NULL,
  `egressInterface` mediumint(9) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=160111 ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `flowstats`
--

CREATE TABLE IF NOT EXISTS `flowstats` (
  `id` bigint(20) unsigned DEFAULT NULL,
  `tcpurg` bigint(20) unsigned DEFAULT NULL,
  `smallpkt` bigint(20) unsigned DEFAULT NULL,
  `largepktct` bigint(20) unsigned DEFAULT NULL,
  `nonempty` bigint(20) unsigned DEFAULT NULL,
  `datalen` bigint(20) unsigned DEFAULT NULL,
  `avgitime` bigint(20) unsigned DEFAULT NULL,
  `firstpktlen` int(10) unsigned DEFAULT NULL,
  `maxpktsize` int(10) unsigned DEFAULT NULL,
  `firsteight` smallint(5) unsigned DEFAULT NULL,
  `stddevlen` bigint(20) unsigned DEFAULT NULL,
  `stddevtime` bigint(20) unsigned DEFAULT NULL,
  `revtcpurg` bigint(20) unsigned DEFAULT NULL,
  `revsmallpkt` bigint(20) unsigned DEFAULT NULL,
  `revnonempty` bigint(20) unsigned DEFAULT NULL,
  `revdatalen` bigint(20) unsigned DEFAULT NULL,
  `revavgitime` bigint(20) unsigned DEFAULT NULL,
  `revfirstpktlen` int(10) unsigned DEFAULT NULL,
  `revlargepktct` bigint(20) unsigned DEFAULT NULL,
  `revmaxpktsize` int(10) unsigned DEFAULT NULL,
  `revstddevlen` bigint(20) unsigned DEFAULT NULL,
  `revstddevtime` bigint(20) unsigned DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `ftp`
--

CREATE TABLE IF NOT EXISTS `ftp` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `http`
--

CREATE TABLE IF NOT EXISTS `http` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `imap`
--

CREATE TABLE IF NOT EXISTS `imap` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `irc`
--

CREATE TABLE IF NOT EXISTS `irc` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `mysql`
--

CREATE TABLE IF NOT EXISTS `mysql` (
  `id` bigint(20) NOT NULL,
  `username` varchar(75) DEFAULT NULL,
  `commandText` varchar(250) DEFAULT NULL,
  `commandCode` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `nntp`
--

CREATE TABLE IF NOT EXISTS `nntp` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `p0f`
--

CREATE TABLE IF NOT EXISTS `p0f` (
  `id` bigint(20) NOT NULL,
  `osName` varchar(100) DEFAULT NULL,
  `osVersion` varchar(50) DEFAULT NULL,
  `osFingerPrint` varchar(50) DEFAULT NULL,
  `reverseOsName` varchar(100) DEFAULT NULL,
  `reverseOsVersion` varchar(50) DEFAULT NULL,
  `reverseOsFingerPrint` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `pop3`
--

CREATE TABLE IF NOT EXISTS `pop3` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `rtsp`
--

CREATE TABLE IF NOT EXISTS `rtsp` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `sip`
--

CREATE TABLE IF NOT EXISTS `sip` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `slp`
--

CREATE TABLE IF NOT EXISTS `slp` (
  `id` bigint(20) NOT NULL,
  `slpVersion` tinyint(3) unsigned DEFAULT NULL,
  `slpMessageType` tinyint(3) unsigned DEFAULT NULL,
  `listType` int(11) DEFAULT NULL,
  `listTypeValue` varchar(150) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `smtp`
--

CREATE TABLE IF NOT EXISTS `smtp` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `ssh`
--

CREATE TABLE IF NOT EXISTS `ssh` (
  `id` bigint(20) NOT NULL,
  `listType` int(11) NOT NULL,
  `listTypeValue` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tcp`
--

CREATE TABLE IF NOT EXISTS `tcp` (
  `id` bigint(20) NOT NULL,
  `tcpSequenceNumber` int(10) unsigned DEFAULT NULL,
  `reverseTcpSequenceNumber` int(10) unsigned DEFAULT NULL,
  `initialTCPFlags` varchar(10) DEFAULT NULL,
  `reverseInitialTCPFlags` varchar(10) DEFAULT NULL,
  `unionTCPFlags` varchar(10) DEFAULT NULL,
  `reverseUnionTCPFlags` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tftp`
--

CREATE TABLE IF NOT EXISTS `tftp` (
  `id` bigint(20) NOT NULL,
  `tftpFilename` varchar(50) DEFAULT NULL,
  `tftpMode` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tls`
--

CREATE TABLE IF NOT EXISTS `tls` (
  `id` bigint(20) NOT NULL,
  `ie` mediumint(8) unsigned DEFAULT NULL,
  `cert_no` tinyint(3) unsigned DEFAULT NULL,
  `data` varchar(500) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
