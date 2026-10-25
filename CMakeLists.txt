cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(janos-web-client)

# Auto-build web UI (npm run build) before creating SPIFFS image
find_program(NPM_BIN npm)
if(NPM_BIN)
    add_custom_target(web_build
        COMMAND ${CMAKE_COMMAND} -E env
            PATH=/opt/homebrew/opt/node@24/bin:$ENV{PATH}
            ${NPM_BIN} run build
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/web
        COMMENT "Building Preact web UI..."
        BYPRODUCTS ${CMAKE_SOURCE_DIR}/spiffs/app.js
                   ${CMAKE_SOURCE_DIR}/spiffs/index.css
                   ${CMAKE_SOURCE_DIR}/spiffs/index.html
    )
endif()

# Flash SPIFFS partition with web assets after build
spiffs_create_partition_image(storage ${CMAKE_SOURCE_DIR}/spiffs FLASH_IN_PROJECT)

if(NPM_BIN)
    add_dependencies(spiffs_storage_bin web_build)
endif()
