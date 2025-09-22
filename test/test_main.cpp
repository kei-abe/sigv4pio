/**
 * @file test_main.cpp
 * @author K.Abe
 * @brief Google Test main function
 */

#include <gtest/gtest.h>

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
