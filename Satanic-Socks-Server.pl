#!/usr/bin/perl 

#                     Satanic Socks Server v0.8.031206-perl 
#    This script is private. Only for SaTaNiC team and friends. Not for sale. 
#                                     Coded by drmist/STNC, web: www.stnc.ru. 

$auth_enabled = 0; 
$auth_login = "user"; 
$auth_pass = "pass"; 
$port = 3003; 

use IO::Socket::INET; 

$SIG{'CHLD'} = 'IGNORE'; 
$bind = IO::Socket::INET->new(Listen=>10, Reuse=>1, LocalPort=>$port) or  die "Can't bind port $port\n"; 

while($client = $bind->accept()) { 
 $client->autoflush(); 

 if(fork()){ $client->close(); } 
 else { $bind->close(); new_client($client); exit(); } 
} 

sub new_client { 
 local $t, $i, $buff, $ord, $success; 
 local $client = $_[0]; 
 sysread($client, $buff, 1); 

 if(ord($buff) == 5) { 
   sysread($client, $buff, 1); 
   $t = ord($buff); 

   unless(sysread($client, $buff, $t) == $t) { return; } 

   $success = 0; 
   for($i = 0; $i < $t; $i++) { 
     $ord = ord(substr($buff, $i, 1)); 
     if($ord == 0 && !$auth_enabled) { 
       syswrite($client, "\x05\x00", 2); 
       $success++; 
       break; 
     } 
     elsif($ord == 2 && $auth_enabled) { 
       unless(do_auth($client)){ return; } 
       $success++; 
       break; 
     } 
   } 

   if($success) { 
     $t = sysread($client, $buff, 3); 

     if(substr($buff, 0, 1) == '\x05') { 
       if(ord(substr($buff, 2, 1)) == 0) { # reserved 
         ($host, $raw_host) = socks_get_host($client); 
         if(!$host) {  return; } 
         ($port, $raw_port) = socks_get_port($client); 
         if(!$port) { return; } 
         $ord = ord(substr($buff, 1, 1)); 
         $buff = "\x05\x00\x00".$raw_host.$raw_port; 
         syswrite($client, $buff, length($buff)); 
         socks_do($ord, $client, $host, $port); 
       } 
     } 
   } else { syswrite($client, "\x05\xFF", 2); }; 
 } 
 $client->close(); 
} 

sub do_auth { 
 local $buff, $login, $pass; 
 local $client = $_[0]; 

 syswrite($client, "\x05\x02", 2); 
 sysread($client, $buff, 1); 

 if(ord($buff) == 1) { 
   sysread($client, $buff, 1); 
   sysread($client, $login, ord($buff)); 
   sysread($client, $buff, 1); 
   sysread($client, $pass, ord($buff)); 

   if($login eq $auth_login && $pass eq $auth_pass) { 
     syswrite($client, "\x05\x00", 2); 
     return 1; 
   } else { syswrite($client, "\x05\x01", 2); } 
 } 

 $client->close(); 
 return 0; 
} 

sub socks_get_host { 
 local $client = $_[0]; 
 local $t, $ord, $raw_host; 
 local $host = ""; 

 sysread($client, $t, 1); 
 $ord = ord($t); 
 if($ord == 1) { 
   sysread($client, $raw_host, 4); 
   @host = $raw_host =~ /(.)/g; 
   $host = ord($host[0]).".".ord($host[1]).".".ord($host[2]).".".ord($host[3]); 
 } elsif($ord == 3) { 
   sysread($client, $raw_host, 1); 
   sysread($client, $host, ord($raw_host)); 
   $raw_host .= $host; 
 } elsif($ord == 4) { 
   #ipv6 - not supported 
 } 

 return ($host, $t.$raw_host); 
} 

sub socks_get_port { 
 local $client = $_[0]; 
 local $raw_port, $port; 
 sysread($client, $raw_port, 2); 
 $port = ord(substr($raw_port, 0, 1)) << 8 | ord(substr($raw_port, 1, 1)); 
 return ($port, $raw_port); 
} 

sub socks_do { 
 local($t, $client, $host, $port) = @_; 

 if($t == 1) { socks_connect($client, $host, $port); } 
 elsif($t == 2) { socks_bind($client, $host, $port); } 
 elsif($t == 3) { socks_udp_associate($client, $host, $port); } 
 else { return 0; } 

 return 1; 
} 

# this part of code was taken from datapipe.pl utility, 
# written by CuTTer (cutter[at]real.xakep.ru) 
# utility lays on cpan.org 

sub socks_connect { 
 my($client, $host, $port) = @_; 
 my $target = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Type => SOCK_STREAM); 

 unless($target) { return; } 

 $target->autoflush(); 
 while($client || $target) { 
   my $rin = ""; 
   vec($rin, fileno($client), 1) = 1 if $client; 
   vec($rin, fileno($target), 1) = 1 if $target; 
   my($rout, $eout); 
   select($rout = $rin, undef, $eout = $rin, 120); 
   if (!$rout  &&  !$eout) { return; } 
   my $cbuffer = ""; 
   my $tbuffer = ""; 

   if ($client && (vec($eout, fileno($client), 1) || vec($rout, fileno($client), 1))) { 
     my $result = sysread($client, $tbuffer, 1024); 
     if (!defined($result) || !$result) { return; } 
   } 

   if ($target  &&  (vec($eout, fileno($target), 1)  || vec($rout, fileno($target), 1))) { 
     my $result = sysread($target, $cbuffer, 1024); 
     if (!defined($result) || !$result) { return; } 
     } 

   if ($fh  &&  $tbuffer) { print $fh $tbuffer; } 

   while (my $len = length($tbuffer)) { 
     my $res = syswrite($target, $tbuffer, $len); 
     if ($res > 0) { $tbuffer = substr($tbuffer, $res); } else { return; } 
   } 

   while (my $len = length($cbuffer)) { 
     my $res = syswrite($client, $cbuffer, $len); 
     if ($res > 0) { $cbuffer = substr($cbuffer, $res); } else { return; } 
   } 
 } 
} 

sub socks_bind { 
 my($client, $host, $port) = @_; 
 # not supported 
} 

sub socks_udp_associate { 
 my($client, $host, $port) = @_; 
 # not supported 
}
