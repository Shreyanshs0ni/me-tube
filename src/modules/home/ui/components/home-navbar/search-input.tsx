import { SearchIcon } from "lucide-react";

export const SearchInput = () => {
  // add search Functionality
  return (
    <form className="flex w-full max-w-[600px]">
      <div className="relative w-full">
        <input
          type="text"
          placeholder="Search"
          className="w-full rounded-l-full border  pl-4 pr-12 py-2 focus:outline-none focus:ring-1 focus:ring-blue-500"
        ></input>
        {/* todo remove search button*/}
      </div>
      <button
        type="submit"
        className="px-5 py-2.5 bg-gray-100 border border-l-0 rounded-r-full hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <SearchIcon className="size-5" />
      </button>
    </form>
  );
};
