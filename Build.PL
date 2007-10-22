use Module::Build;
# See perldoc Module::Build for details of how this works

Module::Build->new
(
    module_name	=> 'Clarion',
    license	=> 'perl',
    requires	=> {
	FileHandle	=> 0,
    },
    build_requires	=> {
	Test::More	=> 0,
    },
    create_makefile_pl => 'traditional',
)->create_build_script;
