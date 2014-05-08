add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/entry
  COMMAND
  as ${PROJECT_SOURCE_DIR}/share/entry.S -o entry.o &&
	ld entry.o -Ttext 0x500 -s -r -o entry.tmp &&
	objcopy -O binary -j .text entry.tmp entry &&
	rm -f entry.tmp

)
add_custom_target(entry ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/entry)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/isr
  COMMAND
  as ${PROJECT_SOURCE_DIR}/share/isr.S -o isr.o &&
	ld isr.o -Ttext 0x500 -s -r -o isr.tmp &&
	objcopy -O binary -j .text isr.tmp isr &&
	rm -f isr.tmp

)
add_custom_target(isr ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/isr)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/signal
  COMMAND
  as ${PROJECT_SOURCE_DIR}/share/signal.S -o signal.o &&
	ld signal.o -Ttext 0x500 -s -r -o signal.tmp &&
	objcopy -O binary -j .text signal.tmp signal &&
	rm -f signal.tmp
)
add_custom_target(signal ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/signal)

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/entry
  ${CMAKE_CURRENT_BINARY_DIR}/isr
  ${CMAKE_CURRENT_BINARY_DIR}/signal
  DESTINATION share/libelkvm)
