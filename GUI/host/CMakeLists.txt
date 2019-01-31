# The CLI isn't used by Textractor itself, but is here for other people that want to build projects on top of Textractor
add_executable(TextractorCLI
	cli.cpp
	exception.cpp
	host.cpp
	textthread.cpp
	util.cpp
)
