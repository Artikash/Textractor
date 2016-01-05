#pragma once

// settings.h
// 8/24/2013 jichi

struct Settings {
  //bool debug; // whether output debug messages using pipes
  int splittingInterval;// time to split text into sentences
  bool clipboardFlag;

  Settings() : splittingInterval(200),
	  clipboardFlag(false)
  {}

};

// EOF
