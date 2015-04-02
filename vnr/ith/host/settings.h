#pragma once

// settings.h
// 8/24/2013 jichi

struct Settings {
  //bool debug; // whether output debug messages using pipes
  int splittingInterval;// time to split text into sentences

  Settings() : splittingInterval(200) {}

};

// EOF
