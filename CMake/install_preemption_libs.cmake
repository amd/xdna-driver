# Use one sample file name for the search
set(PREEMPT_FILE_NAME preempt_save_stx_4x8.bin)

file(GLOB_RECURSE PREEMPT_FILE_PATH ${SEARCH_PATH}/${PREEMPT_FILE_NAME})
if (PREEMPT_FILE_PATH)
  get_filename_component(PREEMPT_FILE_DIR ${PREEMPT_FILE_PATH} DIRECTORY)
  #message(WARNING "Linking ${BIN_DIR}/preemption_libs to ${PREEMPT_FILE_DIR}")
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${PREEMPT_FILE_DIR} ${BIN_DIR}/preemption_libs
    )
else()
  message(FATAL_ERROR "Preemption libs not found!")
endif()
