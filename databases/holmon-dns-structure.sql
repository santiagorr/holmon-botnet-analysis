-- phpMyAdmin SQL Dump
-- version 3.4.11.1deb2
-- http://www.phpmyadmin.net
--
-- Servidor: localhost
-- Tiempo de generación: 15-07-2014 a las 11:03:54
-- Versión del servidor: 5.5.37
-- Versión de PHP: 5.4.4-14+deb7u9

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Base de datos: `holmondns`
--
CREATE DATABASE IF NOT EXISTS `holmondns` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE `holmondns`;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `DNSAdditional`
--

CREATE TABLE IF NOT EXISTS `DNSAdditional` (
  `Query_ID` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `DNSAnswer`
--

CREATE TABLE IF NOT EXISTS `DNSAnswer` (
  `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `Query_ID` int(11) NOT NULL,
  `Type` smallint(1) NOT NULL,
  `Class` smallint(1) NOT NULL,
  `TTL` int(11) NOT NULL,
  `RDlength` int(11) NOT NULL,
  `RDATA` varchar(60) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `Query_ID` (`Query_ID`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `DNSMessageHeader`
--

CREATE TABLE IF NOT EXISTS `DNSMessageHeader` (
  `PacketID` bigint(20) NOT NULL AUTO_INCREMENT,
  `Query_ID` int(11) NOT NULL,
  `QR_flag` bit(1) NOT NULL,
  `R_code` bit(4) NOT NULL,
  `QD_count` int(11) NOT NULL,
  `AN_count` int(11) NOT NULL,
  `NS_count` int(11) NOT NULL,
  `AR_count` int(11) NOT NULL,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `timestamp` bigint(20) NOT NULL,
  `Source_addr` int(16) unsigned NOT NULL,
  `Dest_addr` int(16) unsigned NOT NULL,
  PRIMARY KEY (`PacketID`),
  KEY `Query_ID` (`Query_ID`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2804 ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `DNSNameServers`
--

CREATE TABLE IF NOT EXISTS `DNSNameServers` (
  `Query_ID` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `DNSQuestion`
--

CREATE TABLE IF NOT EXISTS `DNSQuestion` (
  `ID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `Query_ID` int(11) NOT NULL,
  `Q_name` varchar(80) NOT NULL,
  `Q_type` smallint(1) NOT NULL,
  `Q_class` smallint(1) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=3 ;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
