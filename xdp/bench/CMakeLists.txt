add_executable(blackbird_xdp_bench hotpath_bench.cpp)
target_link_libraries(
    blackbird_xdp_bench
    PRIVATE
        benchmark::benchmark
        benchmark::benchmark_main
        blackbird_project_options
        blackbird_project_warnings
)
target_compile_features(blackbird_xdp_bench PRIVATE cxx_std_23)

add_executable(blackbird_xdp_pipeline_bench pipeline_bench.cpp)
target_link_libraries(
    blackbird_xdp_pipeline_bench
    PRIVATE
        benchmark::benchmark
        benchmark::benchmark_main
        blackbird_project_options
        blackbird_project_warnings
)
target_compile_features(blackbird_xdp_pipeline_bench PRIVATE cxx_std_23)
