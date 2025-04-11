# Use one sample file name for the search
set(PREEMPT_FILE_NAME preempt_save_stx_4x8.bin)

file(GLOB_RECURSE PREEMPT_FILE_PATH ${SEARCH_PATH}/${PREEMPT_FILE_NAME})
if (PREEMPT_FILE_PATH)
  get_filename_component(PREEMPT_FILE_DIR ${PREEMPT_FILE_PATH} DIRECTORY)
  
  # Ensure parent directory exists
  get_filename_component(TARGET_PARENT_DIR ${BIN_DIR} DIRECTORY)
  if (NOT EXISTS ${TARGET_PARENT_DIR})
    file(MAKE_DIRECTORY ${TARGET_PARENT_DIR})
  endif()
  
  # Create bins directory if it doesn't exist
  if (NOT EXISTS ${BIN_DIR})
    file(MAKE_DIRECTORY ${BIN_DIR})
  endif()

  # Remove existing symlink if it exists
  if (EXISTS ${BIN_DIR}/preemption_libs)
    file(REMOVE ${BIN_DIR}/preemption_libs)
  endif()

  # Create the symlink and check for errors
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E create_symlink
    ${PREEMPT_FILE_DIR} ${BIN_DIR}/preemption_libs
    RESULT_VARIABLE SYMLINK_RESULT
    ERROR_VARIABLE SYMLINK_ERROR
  )

  if (NOT SYMLINK_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to create symlink: ${SYMLINK_ERROR}")
  endif()
else()
  message(FATAL_ERROR "Preemption libs not found in path: ${SEARCH_PATH}")
endif()
